//#define DEBUGGING

#include "global.h"
#include "sparkWebsocket.h"
#include "sha1.h"
#include "Base64.h"

bool WebSocketClient::handshake(TCPClient *tcp_client) {
	String data;
	
    client = tcp_client;

    // If there is a connected client->
    if (client->connected()) {
        // Check request and look for websocket handshake
#ifdef DEBUGGING
            Serial.println("Client connected");
#endif
        if (analyzeRequest()) {
#ifdef DEBUGGING
                Serial.println("Websocket established");
#endif
                return true;

        }
        else {
            // Might just need to break until out of tcp_client loop.
#ifdef DEBUGGING
            Serial.println("Invalid handshake");
#endif
            disconnectStream();

            return false;
        }
    } else {
        return false;
    }
}

int WebSocketClient::add2buf(char *buf, int bufLen, String str) {
    for (unsigned int i = 0; i < str.length(); i += 1) {
        buf[bufLen] = str.charAt(i);
        bufLen++;
    }
    
    buf[bufLen] = '\0';
    return bufLen;
}

int WebSocketClient::add2buf(char *buf, int bufLen, char *str) {
    for (unsigned int i = 0; i < strlen(str); i += 1) {
        buf[bufLen] = str[i];
        bufLen++;
    }
    
    buf[bufLen] = '\0';
    return bufLen;
}
    
bool WebSocketClient::analyzeRequest() {
    char buf[512];
    int buf_len = 0;
    int bite;
    bool foundupgrade = false;
    char serverKey[29] = "----------------------------";
    char keyStart[17];
    char b64Key[25];
    char key[61] = "------------------------258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char keyHeader[21] = "Sec-WebSocket-Accept";
    char upgradeHeader[19] = "Upgrade: websocket";

    randomSeed(analogRead(0));

    for (int i=0; i<16; ++i) {
        keyStart[i] = (char)random(33, 126);
    }

    base64_encode(b64Key, keyStart, 16);
    
    for (int i=0; i<24; ++i) {
        key[i] = b64Key[i];
    }

#ifdef DEBUGGING
    Serial.println("Sending websocket upgrade headers");
#endif    
    
    buf_len = add2buf(buf, buf_len, "GET ");
    buf_len = add2buf(buf, buf_len, path);
    buf_len = add2buf(buf, buf_len, " HTTP/1.1\r\n");
    buf_len = add2buf(buf, buf_len, "Upgrade: websocket\r\n");
    buf_len = add2buf(buf, buf_len, "Connection: Upgrade\r\n");
    buf_len = add2buf(buf, buf_len, "Origin: Spark\r\n");
    buf_len = add2buf(buf, buf_len, "Host: ");
    buf_len = add2buf(buf, buf_len, host);
    buf_len = add2buf(buf, buf_len, CRLF); 
    buf_len = add2buf(buf, buf_len, "Sec-WebSocket-Key: ");
    buf_len = add2buf(buf, buf_len, b64Key);
    buf_len = add2buf(buf, buf_len, CRLF);
//    buf_len = add2buf(buf, buf_len, "Sec-WebSocket-Protocol: chat\r\n");
    buf_len = add2buf(buf, buf_len, "Sec-WebSocket-Version: 13\r\n");
    buf_len = add2buf(buf, buf_len, CRLF);
    client->write((uint8_t*)buf, buf_len);
    
    buf_len = 0;
    
#ifdef DEBUGGING
    Serial.println("Analyzing response headers");
#endif    

    while (client->connected() && !client->available()) {
        delay(300);
//        Serial.println("Waiting...");
    }

    // TODO: More robust string extraction
    
    while ((bite = client->read()) != -1) {

        buf[buf_len++] = (char)bite;

        if ((char)bite == '\n') {
            buf[buf_len] = '\0';
#ifdef DEBUGGING
            Serial.print("Got Header: ");
            Serial.print(buf);
#endif
			if (strncmp(keyHeader, buf, 20) == 0) {
			    strncpy(serverKey, &buf[22], buf_len - 24);
			    serverKey[buf_len - 24] = '\0';
#ifdef DEBUGGING
				Serial.print("Server key: ");
				Serial.println(serverKey);
#endif
			}
            else if (!foundupgrade && strncmp(upgradeHeader, buf, 18)) {
                foundupgrade = true;
            }
            buf_len = 0;		
        }

        if (!client->available()) {
          delay(20);
        }
    }

#ifdef DEBUGGING
            Serial.print("Key: ");
            Serial.println(key);
#endif
    uint8_t *hash;
    char result[21];
    char b64Result[30];

    Sha1.init();
    Sha1.print(key);
    hash = Sha1.result();

    for (int i=0; i<20; ++i) {
        result[i] = (char)hash[i];
    }
    result[20] = '\0';

    base64_encode(b64Result, result, 20);

#ifdef DEBUGGING
            Serial.print("B64 Result: ");
            Serial.println(b64Result);
#endif
    // if the keys match, good to go
    return (strcmp(serverKey, b64Result) == 0);
}


bool WebSocketClient::handleStream(String& data, uint8_t *opcode) {
    uint8_t msgtype;
    unsigned int length;
    uint8_t mask[4];
    unsigned int i;
    bool hasMask = false;

    if (!client->connected() || !client->available()) {
        return false;
    }      

    msgtype = timedRead();
    if (!client->connected()) {
        return false;
    }

    length = timedRead();

    if (length & WS_MASK) {
        hasMask = true;
        length = length & ~WS_MASK;
    }


    if (!client->connected()) {
        return false;
    }

    if (length == WS_SIZE16) {
        length = timedRead() << 8;
        if (!client->connected()) {
            return false;
        }
            
        length |= timedRead();
        if (!client->connected()) {
            return false;
        }   

    } else if (length == WS_SIZE64) {
#ifdef DEBUGGING
        Serial.println("No support for over 16 bit sized messages");
#endif
        return false;
    }

    if (hasMask) {
        // get the mask
        mask[0] = timedRead();
        if (!client->connected()) {
            return false;
        }

        mask[1] = timedRead();
        if (!client->connected()) {

            return false;
        }

        mask[2] = timedRead();
        if (!client->connected()) {
            return false;
        }

        mask[3] = timedRead();
        if (!client->connected()) {
            return false;
        }
    }
        
    data = "";
        
    if (opcode != NULL)
    {
      *opcode = msgtype & ~WS_FIN;
    }
                
    if (hasMask) {
        for (i=0; i<length; ++i) {
            data += (char) (timedRead() ^ mask[i % 4]);
            if (!client->connected()) {
                return false;
            }
        }
    } else {
        for (i=0; i<length; ++i) {
            data += (char) timedRead();
            if (!client->connected()) {
                return false;
            }
        }            
    }
    
    return true;
}

void WebSocketClient::disconnectStream() {
#ifdef DEBUGGING
    Serial.println("Terminating socket");
#endif
    // Should send 0x8700 to server to tell it I'm quitting here.
    client->write((uint8_t) 0x87);
    client->write((uint8_t) 0x00);
    
    client->flush();
    delay(10);
    client->stop();
}

bool WebSocketClient::getData(String& data, uint8_t *opcode) {
    return handleStream(data, opcode);
}    

void WebSocketClient::sendData(const char *str, uint8_t opcode) {
#ifdef DEBUGGING
    Serial.print("Sending data: ");
    Serial.println(str);
#endif
    if (client->connected()) {
        sendEncodedData(str, opcode);       
    }
}

void WebSocketClient::sendData(String str, uint8_t opcode) {
#ifdef DEBUGGING
    Serial.print("Sending data: ");
    Serial.println(str);
#endif
    if (client->connected()) {
        sendEncodedData(str, opcode);
    }
}

int WebSocketClient::timedRead() {
  while (!client->available()) {
    delay(20);  
  }

  return client->read();
}

void WebSocketClient::sendEncodedData(char *str, uint8_t opcode) {
    uint8_t mask[4];
    int size = strlen(str);

    if (size > 125) {
    	Serial.println("String too long for sending through websocket");
    }
    else {
		// Opcode; final fragment
		client->write(opcode | WS_FIN);
		client->write(((uint8_t) size) | WS_MASK);

		mask[0] = random(0, 256);
		mask[1] = random(0, 256);
		mask[2] = random(0, 256);
		mask[3] = random(0, 256);
	
		client->write(mask[0]);
		client->write(mask[1]);
		client->write(mask[2]);
		client->write(mask[3]);
	 
		for (int i=0; i<size; ++i) {
			client->write(str[i] ^ mask[i % 4]);
		}
    }
}

void WebSocketClient::sendEncodedData(String str, uint8_t opcode) {
    int size = str.length() + 1;
    char cstr[size];
    
// 	Serial.print("sendEncodedData: ");
// 	Serial.println(str);
	
    str.toCharArray(cstr, size);

    sendEncodedData(cstr, opcode);
}
