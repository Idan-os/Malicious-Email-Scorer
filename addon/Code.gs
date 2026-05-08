/**
 * Main entry point for the Gmail Add-on.
 * Called automatically when an email is opened due to contextualTriggers in manifest.
 */
const ANALYZER_URL = "localhost:8080";

// Safety limits to reduce abuse and keep the add-on responsive.
const MAX_RAW_EMAIL_BYTES = 1024 * 1024;
const MAX_REASONING_LENGTH = 240;
const MAX_ALERTS_TO_SHOW = 8;

function onGmailMessageOpen(e) {
  return processMessage(e);
}

function escapeHtml(value) {
  // Escape every user-controlled string before putting it into the card UI.
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function buildErrorCard(title, message) {
  // Return a safe failure state instead of throwing and exposing internals.
  const card = CardService.newCardBuilder();
  const section = CardService.newCardSection();

  section.addWidget(CardService.newTextParagraph().setText(
    `<b>${escapeHtml(title)}</b><br>${escapeHtml(message)}`
  ));

  card.addSection(section);
  card.setHeader(CardService.newCardHeader().setTitle("Email Security Scan"));
  return card.build();
}

function createResultCard(result) {
  const score = Number(result && result.score);
  const reasoning = escapeHtml(((result && result.reasoning) || "No details available.").slice(0, MAX_REASONING_LENGTH));
  const alerts = Array.isArray(result && result.alerts) ? result.alerts.slice(0, MAX_ALERTS_TO_SHOW) : [];
  let color;
  let statusEmoji;

  // Determine color and emoji based on score levels
  if (Number.isNaN(score)) {
    color = "#7f8c8d";
    statusEmoji = "\u2139\ufe0f Unknown";
  } else if (score < 25) {
    color = "#27ae60"; // Green
    statusEmoji = "\u2705 Low Risk";
  } else if (score < 50) {
    color = "#f1c40f"; // Yellow
    statusEmoji = "\u26a0\ufe0f Medium Risk";
  } else if (score < 75) {
    color = "#e67e22"; // Orange
    statusEmoji = "\U0001f7e0 High Risk";
  } else {
    color = "#c0392b"; // Red
    statusEmoji = "\U0001f6a8 Critical Risk";
  }

  const card = CardService.newCardBuilder();
  const header = CardService.newCardHeader()
    .setTitle("Email Security Scan")
    .setSubtitle("Maliciousness Score Analysis");
  
  const section = CardService.newCardSection();
  
  // Using DecoratedText for a cleaner look with colored status
  section.addWidget(CardService.newDecoratedText()
    .setTopLabel("Security Verdict")
    .setText(`Final Score: ${Number.isNaN(score) ? "N/A" : score + "/100"}`)
    .setBottomLabel(reasoning)
    // This adds a colored text highlight to the right side
    .setWrapText(true)
    );

  // Big Color Indicator using HTML formatting in a TextParagraph
  section.addWidget(CardService.newTextParagraph()
    .setText(`<font color="${color}"><b>Status: ${statusEmoji}</b></font>`));

  if (alerts.length > 0) {
    section.addWidget(CardService.newTextParagraph()
      .setText("<b>Flags Detected:</b>\n\u2022 " + alerts.map(escapeHtml).join("\n\u2022 ")));
  } else {
    section.addWidget(CardService.newTextParagraph()
      .setText("No major security flags detected."));
  }

  card.addSection(section);
  card.setHeader(header);
  
  return card.build();
}


function processMessage(e) {
  // Fail closed if Gmail does not provide the expected event shape.
  if (!e || !e.gmail || !e.gmail.accessToken || !e.gmail.messageId) {
    return buildErrorCard("Unable to scan email", "The Gmail event payload was missing required data.");
  }

  const accessToken = e.gmail.accessToken;
  // The access token is required so the add-on can read only the opened message.
  GmailApp.setCurrentMessageAccessToken(accessToken);
  
  const messageId = e.gmail.messageId;
  const message = GmailApp.getMessageById(messageId);
  const rawContent = message.getRawContent();

  // Refuse oversized messages so the scanner cannot be abused with huge payloads.
  if (!rawContent) {
    return buildErrorCard("Unable to scan email", "The message body could not be read.");
  }

  if (rawContent.length > MAX_RAW_EMAIL_BYTES) {
    return buildErrorCard("Unable to scan email", "The email is too large to analyze safely.");
  }
  
  return sendToServer(rawContent);
}


function sendToServer(rawEml) {
  const options = {
    method: "post",
    contentType: "application/json",
    // Send only the raw EML payload, not any other Gmail metadata.
    payload: JSON.stringify({ eml: rawEml }),
    muteHttpExceptions: true
  };
  
  try {
    // Parse the backend response as JSON and fall back to an error card if it fails.
    const response = UrlFetchApp.fetch(ANALYZER_URL, options);
    const result = JSON.parse(response.getContentText());
    return createResultCard(result);
  } catch (error) {
    return buildErrorCard("Scan failed", "The analysis service could not be reached safely.");
  }
}
