package message;

public enum Opcode {

    //COMMON
    OK, //operation successful
    ERROR, //operation failed


    //AUTHENTICATION
    REGISTER, //register a new user
    REGISTER_SUCCESS, //register successful
    CHECK_CREDENTIALS, //check user credentials
    RETURNING_USER, //returning user
    INVALID_CREDENTIALS, //invalid credentials
    ERROR_REGISTERING, //error registering user
    NO_USERS,
    QUIT,

    //CONTACTS
    ADD_CONTACT,
    REMOVE_CONTACT,
    GET_POSSIBLE_CONTACTS,

    //MESSAGES
    SEND_MESSAGE,
    GET_MESSAGES_FROM_USER,
    SEND_E2E_MESSAGE,

    //E2E
    VALIDATE_TOKEN,
    INVALID_TOKEN,
    VALID_TOKEN,


    //LIST
    GET_USERS,

    //DATABASE - they will need to have
    GET_CONTACTS,
    UPDATE_CONTACTS,
    DELETE_CONTACT,
    GET_MESSAGES,
    GET_MESSAGES_FROM_USER_TO_USER,
    PUT_MESSAGE,
    CHECK_USER,
    GET_SALT,
    UPDATE_PUBKEY,
    GET_PUBKEY,
    UPDATE_PRIVKEY,
    GET_PRIVKEY,

}
