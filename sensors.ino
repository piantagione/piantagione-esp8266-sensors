
#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <ESPping.h>
#include <IPAddress.h>
#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/ip.h"
#include "lwip/init.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include <Crypto.h>
#include <Curve25519.h>
#include <RNG.h>
#include <string.h>
#include <ESP8266mDNS.h>
extern "C" {
#include "wireguardif.h"
#include "wireguard-platform.h"
}
#include <Adafruit_Sensor.h>
#include <DHT.h>

static uint8_t m_publicKey[32];
static uint8_t m_privateKey[32];

static struct netif wg_netif_struct = {0};
static struct netif *wg_netif = NULL;
static uint8_t wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;
IPAddress ipaddr(1, 2, 3, 4); 
IPAddress netmask(255, 255, 255, 0);
IPAddress gw(1,2,3,4);
//IPAddress dns1(8, 8, 8, 8);
const char* target_ip = "REDACTED";

const char* private_key = "REDACTED";
const char* public_key = "REDACTED"; // server's pubkey
int endpoint_port = 51820;  // [Peer] Endpoint

String HTMLpage;
// Replace with your network credentials
const char* ssid = "REDACTED"; 
const char* password = "REDACTED"; 

float t = 0.0;
float h = 0.0;

#define DHTPIN 5     // Digital pin connected to the DHT sensor

#define DHTTYPE    DHT21  //or DHT11, DHT22

DHT dht(DHTPIN, DHTTYPE);


class WireGuard
{
  public:
    void begin();
     private:
       void wg_netif_set_ipaddr(struct netif *data, uint32_t addr);
       void wg_netif_set_netmask(struct netif *data, uint32_t addr);
       void wg_netif_set_gw(struct netif *data, uint32_t addr);
       void wg_netif_set_up(struct netif *data);
  private:
    void wg_if_add_dns(uint32_t addr);
    void wg_if_clear_dns(void);
};

void ICACHE_FLASH_ATTR
WireGuard::wg_netif_set_ipaddr(struct netif *data, uint32_t addr)
{
 ip_addr_t ipaddr;
 ipaddr.addr = addr;
 netif_set_ipaddr(data, &ipaddr);
}

void ICACHE_FLASH_ATTR
WireGuard::wg_netif_set_netmask(struct netif *data, uint32_t addr)
{
 ip_addr_t ipaddr;
 ipaddr.addr = addr;
 netif_set_netmask(data, &ipaddr);
}

void ICACHE_FLASH_ATTR
WireGuard::wg_netif_set_gw(struct netif *data, uint32_t addr)
{
 ip_addr_t ipaddr;
 ipaddr.addr = addr;
 netif_set_gw(data, &ipaddr);
}

void ICACHE_FLASH_ATTR
WireGuard::wg_netif_set_up(struct netif *data)
{
 netif_set_up(data);
}

static int dns_count;

void ICACHE_FLASH_ATTR
WireGuard::wg_if_clear_dns(void)
{
  ip_addr_t addr;
   addr.addr = INADDR_ANY;
  int i;
  for (i = 0; i < DNS_MAX_SERVERS; i++)
    dns_setserver(i, &addr);
  dns_count = 0;
}

void ICACHE_FLASH_ATTR
WireGuard::wg_if_add_dns(uint32_t addr)
{
  ip_addr_t ipaddr;
#ifdef ESP8266
  ipaddr.addr = addr;
#else
  ipaddr.u_addr.ip4.addr = addr;
#endif
  dns_setserver(dns_count++, &ipaddr);
}

void WireGuard::begin() {
  struct wireguardif_init_data wg;
  struct wireguardif_peer peer;
  ip_addr_t _ipaddr = IPADDR4_INIT(static_cast<uint32_t>(ipaddr));
  ip_addr_t _netmask = IPADDR4_INIT(static_cast<uint32_t>(netmask));
  ip_addr_t _gateway = IPADDR4_INIT(static_cast<uint32_t>(gw));
  // Setup the WireGuard device structure
  wg.private_key = private_key;
  wg.listen_port = endpoint_port;
  wg.bind_netif = NULL;// if ethernet use eth netif
  // Initialise the first WireGuard peer structure
  wireguardif_peer_init(&peer);
  // Register the new WireGuard network interface with lwIP

  wg_netif = netif_add(&wg_netif_struct, ip_2_ip4(&_ipaddr), ip_2_ip4(&_netmask), ip_2_ip4(&_gateway), &wg, &wireguardif_init, &ip_input);

  if ( wg_netif == nullptr ) {
    Serial.println("failed to initialize WG netif.");
    return;
  }
  // Mark the interface as administratively up, link up flag is set automatically when peer connects
  //wg_netif_set_up(wg_netif); // alternate netif
  netif_set_up(wg_netif);
  //wg_if_add_dns(dns1);

  peer.public_key = public_key;
  peer.preshared_key = NULL;
  // Allow all IPs through tunnel
  //  peer.allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
  //  peer.allowed_mask = IPADDR4_INIT_BYTES(0, 0, 0, 0);
  {
    ip_addr_t allowed_ip = IPADDR4_INIT_BYTES(1, 2, 3, 4);
    peer.allowed_ip = allowed_ip;
    ip_addr_t allowed_mask = IPADDR4_INIT_BYTES(255, 255, 255, 0); //chancge accordingly
    peer.allowed_mask = allowed_mask;
  }
  IPAddress IP;
  WiFi.hostByName("REDACTED", IP);
  Serial.println(IP[0]);
  // If we know the endpoint's address can add here
  peer.endpoint_ip = IPADDR4_INIT_BYTES(IP[0], IP[1], IP[2], IP[3]);
  peer.endport_port = endpoint_port;

  // Register the new WireGuard peer with the netwok interface
  wireguardif_add_peer(wg_netif, &peer, &wireguard_peer_index);

  if ((wireguard_peer_index != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&peer.endpoint_ip)) {
    // Start outbound connection to peer
    wireguardif_connect(wg_netif, wireguard_peer_index);

    delay(100);
    netif_set_default(wg_netif);
    bool pingResult= Ping.ping(target_ip); 

  if (pingResult) {
    Serial.println("Ping successful!");
  } else {
    Serial.println("Ping failed!");
  }


    delay(100);
    Serial.println("wireguard start completed");
  } else if (wireguard_peer_index == WIREGUARDIF_INVALID_INDEX) {
    Serial.println("wireguard if invalid index");
  } else if (ip_addr_isany(&peer.endpoint_ip)) {
    Serial.println("wireguard endpoint ip not found");
  }
}

static WireGuard wg;
ESP8266WebServer server(80);

static const char *base64_lookup = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


void handleNotFound() {
  String message = "File Not Found\n\n";
  message += "URI: ";
  message += server.uri();
  message += "\nMethod: ";
  message += (server.method() == HTTP_GET) ? "GET" : "POST";
  message += "\nArguments: ";
  message += server.args();
  message += "\n";
  for (uint8_t i = 0; i < server.args(); i++) {
    message += " " + server.argName(i) + ": " + server.arg(i) + "\n";
  }
  server.send(404, "text/plain", message);
  
}



// Generally, you should use "unsigned long" for variables that hold time
// The value will quickly become too large for an int to store
unsigned long previousMillis = 0;    // will store last time DHT was updated

// Updates DHT readings every 10 seconds
const long interval = 10000;  


// Replaces placeholder with DHT values
String processor(const String& var){
  Serial.println(var);
  if(var == "TEMPERATURE"){
    return String(t);
  }
  else if(var == "HUMIDITY"){
    return String(h);
  }
  return String();
}

void setup() {

// current temperature & humidity, updated in loop()
//HTMLpage += "<head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> <link rel=\"stylesheet\" href=\"https://use.fontawesome.com/releases/v5.7.2/css/all.css\" integrity=\"sha384-fnmOCqbTlWIlj8LyTjo7mOUStjsKC4pOpQbqyi7RrhN7udi9RwhKkMHpvLbHG9Sr\" crossorigin=\"anonymous\"><style>  html {  font-family: Arial;  display: inline-block;  margin: 0px auto;  text-align: center;  }   h2 { font-size: 3.0rem;  p { font-size: 3.0rem; } .units { font-size: 1.2rem; }.dht-labels{font-size: 1.5rem;vertical-align:middle;padding-bottom: 15px;} </style></head><body><h2>ESP8266 DHT Server</h2><p><i class=\"fas fa-thermometer-half\" style=\"color:#059e8a;\"></i> <span class=\"dht-labels\">Temperature</span>  <span id=\"temperature\">%TEMPERATURE%</span><sup class=\"units\">&deg;C</sup> </p><p><i class=\"fas fa-tint\" style=\"color:#00add6;\"></i> <span class=\"dht-labels\">Humidity</span><span id=\"humidity\">%HUMIDITY%</span><sup class=\"units\">%</sup></p></body><script> setInterval(function ( ) {var xhttp = new XMLHttpRequest(); xhttp.onreadystatechange = function() { if (this.readyState == 4 && this.status == 200) { document.getElementById(\"temperature\").innerHTML = this.responseText;  }}; xhttp.open(\"GET\", \"/temperature\", true);xhttp.send();}, 10000 ) ;setInterval(function ( ) {var xhttp = new XMLHttpRequest();xhttp.onreadystatechange = function() {if (this.readyState == 4 && this.status == 200) {document.getElementById(\"humidity\").innerHTML = this.responseText; }};xhttp.open(\"GET\", \"/humidity\", true);xhttp.send();}, 10000 ) ;</script></html>";
HTMLpage += "<head><title>Light Webserver</title></head><h3>ESP8266 Webserver (Sensors)</h3><p>led <a href=\"temperature\"><button>T</button></a> <a href=\"humidity\"><button>h</button></a></p>";
  Serial.begin(115200);
  dht.begin();
  WiFi.mode(WIFI_STA); 
  WiFi.begin(ssid,password);
  Serial.println("");

  // Wait for connection
  
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("");
  Serial.print("Connected to ");
  Serial.println(ssid);
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());

  if (MDNS.begin("esp8266", WiFi.localIP())) {
    Serial.println("MDNS responder started");
  }

  

  /* If the device is behind NAT or stateful firewall, set persistent_keepalive.
    persistent_keepalive is disabled by default */
  // wg_config.persistent_keepalive = 10;
  wg.begin();

  // Start server

  server.on("/", []() {
    server.send(200, "text/html", HTMLpage);
  });
  server.on("/temperature",[]() {
    server.send(200, "text/plain", processor("TEMPERATURE"));

    delay(1000);
  });
  server.on("/humidity",[]() {
    server.send(200, "text/plain", processor("HUMIDITY"));
    delay(1000);
  });

  server.begin();
  Serial.println("HTTP Webserver started");
}
 
void loop(){  
  unsigned long currentMillis = millis();
  if (currentMillis - previousMillis >= interval) {
    // save the last time you updated the DHT values
    previousMillis = currentMillis;
    // Read temperature as Celsius (the default)
    float newT = dht.readTemperature();
    // Read temperature as Fahrenheit (isFahrenheit = true)
    //float newT = dht.readTemperature(true);
    // if temperature read failed, don't change t value
    if (isnan(newT)) {
      Serial.println("Failed to read from DHT sensor!");
    }
    else {
      t = newT;
      Serial.println(t);
    }
    // Read Humidity
    float newH = dht.readHumidity();
    // if humidity read failed, don't change h value 
    if (isnan(newH)) {
      Serial.println("Failed to read from DHT sensor!");
    }
    else {
      h = newH;
      Serial.println(h);

    }
  }
    server.handleClient();

} 



