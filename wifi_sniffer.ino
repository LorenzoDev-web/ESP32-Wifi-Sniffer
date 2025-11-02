/*
This code was programmed by: Lorenzo Egidio.
To use the sniffer,
you just need to have the Arduino IDE 
(or similar that has a serial monitor)
to be able to use the sniffer.
*/

#include <esp_wifi.h>
#include <WiFi.h>
#include <Preferences.h>

#define MAX_REDES 20
#define MAX_CLIENTES 20
#define CHANNEL_MIN 1
#define CHANNEL_MAX 13
#define CHANNEL_SWITCH_INTERVAL 3000

Preferences preferences;

struct Cliente {
  String mac;
  uint8_t tipo;
  uint8_t subtipo;
};

struct Rede {
  String ssid;
  uint8_t bssid[6];
  uint8_t canal;
  int8_t rssi;
  Cliente clientes[MAX_CLIENTES];
  int clientesCount;
};

Rede redes[MAX_REDES];
int redesCount = 0;
int currentChannel = CHANNEL_MIN;
unsigned long lastChannelSwitch = 0;
bool snifferAtivo = false;

// Função para converter MAC para string
String macToString(const uint8_t* mac) {
  char buf[18];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

// Compara dois MACs
bool macEqual(const uint8_t* mac1, const uint8_t* mac2) {
  for (int i = 0; i < 6; i++) {
    if (mac1[i] != mac2[i]) return false;
  }
  return true;
}

// Procura rede por BSSID, retorna índice ou -1
int findRedeByBSSID(const uint8_t* bssid) {
  for (int i = 0; i < redesCount; i++) {
    if (macEqual(redes[i].bssid, bssid)) return i;
  }
  return -1;
}

// Extrai o SSID do Beacon
String getSSID(const uint8_t* payload, int len) {
  int pos = 36; // Início IEs
  while (pos < len) {
    uint8_t id = payload[pos];
    uint8_t ie_len = payload[pos + 1];
    if (id == 0 && ie_len > 0 && (pos + 2 + ie_len) <= len) {
      char ssid[33] = {0};
      memcpy(ssid, &payload[pos + 2], ie_len);
      return String(ssid);
    }
    pos += 2 + ie_len;
  }
  return String("");
}

// Extrai o canal da rede do IE com ID 3 (DS Parameter Set)
uint8_t getChannel(const uint8_t* payload, int len) {
  int pos = 36;
  while (pos < len) {
    uint8_t id = payload[pos];
    uint8_t ie_len = payload[pos + 1];
    if (id == 3 && ie_len == 1 && (pos + 2 + ie_len) <= len) {
      return payload[pos + 2];
    }
    pos += 2 + ie_len;
  }
  return 0; // desconhecido
}

// Traduz o tipo do frame para texto
String tipoToString(uint8_t tipo) {
  switch (tipo) {
    case 0: return "Management";
    case 1: return "Control";
    case 2: return "Data";
    default: return "Reserved";
  }
}

// Traduz o subtipo do frame para texto, dependendo do tipo
String subtipoToString(uint8_t tipo, uint8_t subtipo) {
  if (tipo == 0) { // Management
    switch (subtipo) {
      case 0: return "Association Request";
      case 1: return "Association Response";
      case 2: return "Reassociation Request";
      case 3: return "Reassociation Response";
      case 4: return "Probe Request";
      case 5: return "Probe Response";
      case 8: return "Beacon";
      case 9: return "ATIM";
      case 10: return "Disassociation";
      case 11: return "Authentication";
      case 12: return "Deauthentication";
      default: return "Unknown Management";
    }
  }
  else if (tipo == 1) { // Control
    switch (subtipo) {
      case 7: return "Control Wrapper";
      case 8: return "Block Ack Request";
      case 9: return "Block Ack";
      case 10: return "PS Poll";
      case 11: return "RTS";
      case 12: return "CTS";
      case 13: return "ACK";
      case 14: return "CF-End";
      case 15: return "CF-End + CF-Ack";
      default: return "Unknown Control";
    }
  }
  else if (tipo == 2) { // Data
    switch (subtipo) {
      case 0: return "Data";
      case 1: return "Data + CF-Ack";
      case 2: return "Data + CF-Poll";
      case 3: return "Data + CF-Ack + CF-Poll";
      case 4: return "Null";
      case 5: return "CF-Ack (No data)";
      case 6: return "CF-Poll (No data)";
      case 7: return "CF-Ack + CF-Poll (No data)";
      case 8: return "QoS Data";
      case 9: return "QoS Data + CF-Ack";
      case 10: return "QoS Data + CF-Poll";
      case 11: return "QoS Data + CF-Ack + CF-Poll";
      case 12: return "QoS Null";
      case 13: return "Reserved";
      case 14: return "QoS CF-Poll";
      case 15: return "QoS CF-Ack + CF-Poll";
      default: return "Unknown Data";
    }
  }
  return "Unknown";
}

// Adiciona ou atualiza cliente na rede
void addOrUpdateCliente(Rede &rede, const String &mac, uint8_t tipo, uint8_t subtipo) {
  for (int i = 0; i < rede.clientesCount; i++) {
    if (rede.clientes[i].mac == mac) {
      rede.clientes[i].tipo = tipo;
      rede.clientes[i].subtipo = subtipo;
      return;
    }
  }
  if (rede.clientesCount < MAX_CLIENTES) {
    rede.clientes[rede.clientesCount].mac = mac;
    rede.clientes[rede.clientesCount].tipo = tipo;
    rede.clientes[rede.clientesCount].subtipo = subtipo;
    rede.clientesCount++;
  }
}

void snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!snifferAtivo) return;

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  const uint8_t *payload = pkt->payload;
  int len = pkt->rx_ctrl.sig_len;

  if (type == WIFI_PKT_MGMT) {
    if ((payload[0] & 0xF0) == 0x80) { // Beacon frame
      int redeIdx = findRedeByBSSID(&payload[10]);
      if (redeIdx == -1 && redesCount < MAX_REDES) {
        Rede &novaRede = redes[redesCount];
        novaRede.ssid = getSSID(payload, len);
        memcpy(novaRede.bssid, &payload[10], 6);
        novaRede.canal = getChannel(payload, len);
        novaRede.rssi = pkt->rx_ctrl.rssi;
        novaRede.clientesCount = 0;
        redesCount++;
        Serial.printf("Nova rede: SSID: %s | BSSID: %s | Canal: %d | RSSI: %d dBm\n",
                      novaRede.ssid.c_str(), macToString(novaRede.bssid).c_str(),
                      novaRede.canal, novaRede.rssi);
      }
    }
  }
  else if (type == WIFI_PKT_DATA) {
    uint8_t frame_ctrl = payload[0];
    uint8_t tipo = (frame_ctrl & 0x03);
    uint8_t subtipo = (frame_ctrl >> 4) & 0x0F;

    String bssid = macToString(&payload[16]);
    String clienteMac = macToString(&payload[10]);

    int redeIdx = findRedeByBSSID(&payload[16]);
    if (redeIdx != -1) {
      addOrUpdateCliente(redes[redeIdx], clienteMac, tipo, subtipo);
      Serial.printf("Cliente na rede %s: %s | Tipo: %s | Subtipo: %s\n",
                    redes[redeIdx].ssid.c_str(), clienteMac.c_str(),
                    tipoToString(tipo).c_str(),
                    subtipoToString(tipo, subtipo).c_str());
    }
  }
}

void salvarDados() {
  preferences.begin("wifiSniffer", false);
  preferences.clear();

  for (int i = 0; i < redesCount; i++) {
    String chaveRede = "rede" + String(i);
    String dados = redes[i].ssid + "," +
                   macToString(redes[i].bssid) + "," +
                   String(redes[i].canal) + "," +
                   String(redes[i].rssi) + "," +
                   String(redes[i].clientesCount);

    for (int c = 0; c < redes[i].clientesCount; c++) {
      dados += "," + redes[i].clientes[c].mac + "," + 
               String(redes[i].clientes[c].tipo) + "," + 
               String(redes[i].clientes[c].subtipo);
    }

    preferences.putString(chaveRede.c_str(), dados);
  }

  preferences.putInt("redesCount", redesCount);
  preferences.end();
  Serial.println("Dados salvos na memória flash!");
}

void carregarDados() {
  preferences.begin("wifiSniffer", true);
  redesCount = preferences.getInt("redesCount", 0);
  if (redesCount > MAX_REDES) redesCount = MAX_REDES;

  for (int i = 0; i < redesCount; i++) {
    String chaveRede = "rede" + String(i);
    String dados = preferences.getString(chaveRede.c_str(), "");
    if (dados.length() == 0) continue;

    int idx1 = dados.indexOf(',');
    int idx2 = dados.indexOf(',', idx1 + 1);
    int idx3 = dados.indexOf(',', idx2 + 1);
    int idx4 = dados.indexOf(',', idx3 + 1);

    redes[i].ssid = dados.substring(0, idx1);
    String macStr = dados.substring(idx1 + 1, idx2);
    sscanf(macStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &redes[i].bssid[0], &redes[i].bssid[1], &redes[i].bssid[2],
           &redes[i].bssid[3], &redes[i].bssid[4], &redes[i].bssid[5]);
    redes[i].canal = dados.substring(idx2 + 1, idx3).toInt();
    redes[i].rssi = dados.substring(idx3 + 1, idx4).toInt();

    redes[i].clientesCount = 0;
    int pos = idx4 + 1;
    while (pos < dados.length() && redes[i].clientesCount < MAX_CLIENTES) {
      int nextMac = dados.indexOf(',', pos);
      if (nextMac == -1) break;
      String macCliente = dados.substring(pos, nextMac);
      pos = nextMac + 1;

      int nextTipo = dados.indexOf(',', pos);
      if (nextTipo == -1) break;
      int tipoCliente = dados.substring(pos, nextTipo).toInt();
      pos = nextTipo + 1;

      int nextSubtipo = dados.indexOf(',', pos);
      String subtipoStr;
      if (nextSubtipo == -1) {
        subtipoStr = dados.substring(pos);
        pos = dados.length();
      } else {
        subtipoStr = dados.substring(pos, nextSubtipo);
        pos = nextSubtipo + 1;
      }
      int subtipoCliente = subtipoStr.toInt();

      redes[i].clientes[redes[i].clientesCount].mac = macCliente;
      redes[i].clientes[redes[i].clientesCount].tipo = tipoCliente;
      redes[i].clientes[redes[i].clientesCount].subtipo = subtipoCliente;
      redes[i].clientesCount++;
    }
  }
  preferences.end();

  Serial.println("Dados carregados da memória flash:");
  for (int i = 0; i < redesCount; i++) {
    Serial.printf("Rede %d: SSID: %s | BSSID: %s | Canal: %d | RSSI: %d dBm\n",
                  i, redes[i].ssid.c_str(), macToString(redes[i].bssid).c_str(),
                  redes[i].canal, redes[i].rssi);
    Serial.println("Clientes:");
    for (int c = 0; c < redes[i].clientesCount; c++) {
      Serial.printf("  MAC: %s | Tipo: %s | Subtipo: %s\n",
                    redes[i].clientes[c].mac.c_str(),
                    tipoToString(redes[i].clientes[c].tipo).c_str(),
                    subtipoToString(redes[i].clientes[c].tipo, redes[i].clientes[c].subtipo).c_str());
    }
  }
}

void limparDados() {
  preferences.begin("wifiSniffer", false);
  preferences.clear();
  preferences.end();
  redesCount = 0;
  Serial.println("Dados da memória flash apagados!");
}

void ligarSniffer() {
  if (!snifferAtivo) {
    esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    lastChannelSwitch = millis();
    snifferAtivo = true;
    Serial.println("Sniffer ligado.");
  }
}

void desligarSniffer() {
  if (snifferAtivo) {
    esp_wifi_set_promiscuous(false);
    snifferAtivo = false;
    Serial.println("Sniffer desligado.");
  }
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_MODE_STA);

  carregarDados();

  snifferAtivo = false;

  Serial.println("Digite '1' para ligar sniffer, '0' para desligar, '9' para apagar dados.");
}

void loop() {
  if (snifferAtivo && millis() - lastChannelSwitch > CHANNEL_SWITCH_INTERVAL) {
    currentChannel++;
    if (currentChannel > CHANNEL_MAX) currentChannel = CHANNEL_MIN;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    lastChannelSwitch = millis();
    Serial.printf("Canal trocado para %d\n", currentChannel);

    salvarDados();
  }

  if (Serial.available()) {
    char c = Serial.read();
    if (c == '1') {
      ligarSniffer();
    } else if (c == '0') {
      desligarSniffer();
    } else if (c == '9') {
      limparDados();
    }
  }
}
