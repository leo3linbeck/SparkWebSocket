bool openWebsocket() {
    // Connect to the websocket server
    if (client.connect(serverIP, serverPort)) {
        Serial.println("Connected to websocket server");
        
        // Handshake with the server
        websocketClient.path = websocketPath;
        websocketClient.host = server;
      
        if (websocketClient.handshake(&client)) {
            Serial.println("Websocket established.");
            send_data_to_websocket((String) strcat(websocketInit, serial_number));
            start_time = millis();
            return true;
        }
        else {
            Serial.println("Handshake failed.");
            client.stop();
        }
    }
    else {
        Serial.println("Connection failed.");
    }

    return false;
}

void send_data_to_websocket(String data) {
    Serial.print("Sending data to websocket: ");
    Serial.println(data);
    websocketClient.sendData(data);
}

void pingWebsocket() {
    unsigned long elapsed_time = millis() - start_time;
    if ((elapsed_time - last_ping) > ping_interval) {
        last_ping = elapsed_time;
        send_data_to_websocket("PING");
    }
}
  
void websocket_loop() {
    String data;
    int retries = 5;
    
    if (client.connected()) {
      
        websocketClient.getData(data);
        while (data.length() > 0) {
            Serial.println("Websocket message received from server.");
            queue_message(data);
            data = "";
            websocketClient.getData(data);
      }
      
      pingWebsocket();  
    }
    else {
        Serial.println("Client disconnected. Will try to re-establish connection");
        while (retries-- > 0) {
            if (openWebsocket()) {
                retries = 0;
            }
        }
    }
}
