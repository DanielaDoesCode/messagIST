package message;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import com.google.gson.*;

public class Message {

    private static String MESSAGE_FIELD = "message";

    private static String SENDER_FIELD = "sender";
    private static String RECEIVER_FIELD = "receiver";
    private static String TIMESTAMP_FIELD = "timestamp";
    private static String CONTENT_FIELD = "content";
    private static String KEY_FIELD = "keyForReceiver";

    private JsonObject jsonObject;

    public Message(String content, String receiver) {
        this.jsonObject = new JsonObject();

        LocalDateTime timestamp = LocalDateTime.now();

        JsonObject messageObject = new JsonObject();
        messageObject.addProperty(RECEIVER_FIELD, receiver);
        messageObject.addProperty(TIMESTAMP_FIELD, timestamp.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        messageObject.addProperty(CONTENT_FIELD, content);

        jsonObject.add(MESSAGE_FIELD, messageObject);
    }

    public Message(String serializedMessage) {
        this.jsonObject = JsonParser.parseString(serializedMessage).getAsJsonObject();
    }

    private JsonObject getMessageObject() {
        JsonObject messageObject = jsonObject.get(MESSAGE_FIELD).getAsJsonObject();
        return messageObject;
    }

    public String getSender() {
        JsonObject messageObject = getMessageObject();
        return messageObject.get(SENDER_FIELD).getAsString();
    }

    public void setSender(String sender) {
        JsonObject messageObject = getMessageObject();
        messageObject.addProperty(SENDER_FIELD, sender);
    }

    public String getReceiver() {
        JsonObject messageObject = getMessageObject();
        return messageObject.get(RECEIVER_FIELD).getAsString();
    }

    public LocalDateTime getTimestamp() {
        JsonObject messageObject = getMessageObject();
        return LocalDateTime.parse(messageObject.get(TIMESTAMP_FIELD).getAsString());
    }

    public String getContent() {
        JsonObject messageObject = getMessageObject();
        return messageObject.get(CONTENT_FIELD).getAsString();
    }

    public boolean isEncrypted() {
        JsonObject messageObject = getMessageObject();
        return messageObject.has(KEY_FIELD);
    }

    public String toString() {
        return jsonObject.toString();
    }
}
