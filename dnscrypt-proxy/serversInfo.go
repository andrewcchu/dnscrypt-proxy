package main

import (
    crypto_rand "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "math/rand"
    "net"
    "net/url"
    "sort"
    "strings"
    "sync"
    "time"
    "hash/fnv"
    "reflect"

    "github.com/VividCortex/ewma"
    "github.com/jedisct1/dlog"
    stamps "github.com/jedisct1/go-dnsstamps"
    "github.com/miekg/dns"
    "golang.org/x/crypto/ed25519"
)

const (
    RTTEwmaDecay = 10.0
)

type RegisteredServer struct {
    name        string
    stamp       stamps.ServerStamp
    description string
}

type ServerBugs struct {
    fragmentsBlocked bool
}

type DOHClientCreds struct {
    clientCert string
    clientKey  string
    rootCA     string
}

type ServerInfo struct {
    Proto              stamps.StampProtoType
    MagicQuery         [8]byte
    ServerPk           [32]byte
    SharedKey          [32]byte
    CryptoConstruction CryptoConstruction
    Name               string
    Timeout            time.Duration
    URL                *url.URL
    HostName           string
    UDPAddr            *net.UDPAddr
    TCPAddr            *net.TCPAddr
    RelayUDPAddr       *net.UDPAddr
    RelayTCPAddr       *net.TCPAddr
    knownBugs          ServerBugs
    lastActionTS       time.Time
    rtt                ewma.MovingAverage
    initialRtt         int
    useGet             bool
    DOHClientCreds     DOHClientCreds
}

type LBStrategy interface {
    getCandidate(serversCount int) int
}

type LBStrategyP2 struct{}

func (LBStrategyP2) getCandidate(serversCount int) int {
    return rand.Intn(Min(serversCount, 2))
}

type LBStrategyPN struct{ n int }

func (s LBStrategyPN) getCandidate(serversCount int) int {
    return rand.Intn(Min(serversCount, s.n))
}

type LBStrategyPH struct{}

func (LBStrategyPH) getCandidate(serversCount int) int {
    return rand.Intn(Max(Min(serversCount, 2), serversCount/2))
}

type LBStrategyFirst struct{}

func (LBStrategyFirst) getCandidate(int) int {
    return 0
}

type LBStrategyRandom struct{}

func (LBStrategyRandom) getCandidate(serversCount int) int {
    return rand.Intn(serversCount)
}

type LBStrategyRR struct{ }

func (LBStrategyRR) getCandidate(serversCount int) int {
    return 0
}

type LBStrategyHash struct{ }

func (LBStrategyHash) getCandidate(serversCount int) int {
    return 0
}

type LBStrategyLocationAvoidant struct{ }

func (LBStrategyLocationAvoidant) getCandidate(serversCount int) int {
    return 0
}

var DefaultLBStrategy = LBStrategyP2{}

// Map/dictionary -- key: string of country abbrev. | value: map/dict. w/ key: IP; value: array of metadata (index 0: specific location, index 1: ASN #, index 2: ASN name)
var denylist = map[string]map[string][]string{
    "af": map[string][]string{
        "180.94.94.194": {"Kabul, Kabul", "AS55330", "AFGHANTELECOM GOVERNMENT COMMUNICATION NETWORK"},
        "117.104.227.243": {"Mazar-e Sharif, Balkh", "AS55424", "Instatelecom Limited"},
    },
    "ax": map[string][]string{
        "194.110.177.46": {"Mariehamn, Mariehamn", "AS3238", "Alands Telekommunikation Ab"},
    },
    "al": map[string][]string{
        "217.24.255.134": {"Tirana, Tirane", "AS42313", "Albtelecom Sh.a."},
        "213.163.127.229": {"Tirana, Tirane", "AS8661", "Telekomi i Kosoves SH.A."},
    },
    "dz": map[string][]string{
        "193.194.70.66": {"Algiers, Alger", "AS3208", "Algerian Academic Research Network"},
        "105.235.131.105": {"Algiers, Alger", "AS33779", "Wataniya Telecom Algerie"},
        "105.235.131.80": {"Algiers, Alger", "AS33779", "Wataniya Telecom Algerie"},
    },
    "ad": map[string][]string{
        "85.94.178.198": {"Les Escaldes, Escaldes-Engordany", "AS6752", "ANDORRA TELECOM SAU"},
        "194.158.78.137": {"Andorra la Vella, Andorra la Vella", "AS6752", "ANDORRA TELECOM SAU"},
    },
    "ai": map[string][]string{
        "69.57.230.68": {"Castries, Castries", "AS15344", "Karib Cable"},
    },
    "aq": map[string][]string{
        "185.121.177.177": {"Auckland, Auckland", "AS204136", "Kevin Holly trading as Silent Ghost e.U."},
    },
    "ar": map[string][]string{
        "186.148.128.86": {"Bahia Blanca, Buenos Aires", "AS52279", "ETERNET S.R.L."},
        "190.151.144.21": {"Campana, Buenos Aires", "AS52339", "Lima Video Cable S.A. (Cabletel)"},
        "200.45.48.233": {"Buenos Aires, Ciudad Autonoma de Buenos Aires", "AS7303", "Telecom Argentina S.A."},
        "181.14.245.186": {"Buenos Aires, Ciudad Autonoma de Buenos Aires", "AS7303", "Telecom Argentina S.A."},
        "200.45.184.43": {"General Cabrera, Cordoba", "AS7303", "Telecom Argentina S.A."},
        "200.110.130.195": {"Buenos Aires, Ciudad Autonoma de Buenos Aires", "AS18747", "IFX Corporation"},
        "179.60.232.10": {"Rosario, Santa Fe", "AS263693", "WICORP SA"},
        "170.210.83.110": {"Buenos Aires, Ciudad Autonoma de Buenos Aires", "AS4270", "Red de Interconexion Universitaria"},
        "200.55.54.234": {"Buenos Aires, Ciudad Autonoma de Buenos Aires", "AS3549", "Level 3 Parent, LLC"},
        "200.110.130.194": {"Buenos Aires, Ciudad Autonoma de Buenos Aires", "AS18747", "IFX Corporation"},
        "186.38.56.11": {"Puerto Ibicuy, Entre Rios", "AS22927", "Telefonica de Argentina"},
        "181.110.241.74": {"Cordoba, Cordoba ", "AS7303", "Telecom Argentina S.A."},
        "157.92.190.15": {"Buenos Aires, Ciudad Autonoma de Buenos Aires", "AS3449", "Universidad Nacional de Buenos Aires"},
        "190.57.234.194": {"Ciudad Autonoma de Buenos Aires", "AS20207", "Gigared S.A."},
        "186.153.180.148": {"Villaguay, Entre Rios", "AS7303", "Telecom Argentina S.A."},
        "179.60.235.209": {"Victoria, Entre Rios", "AS263693", "WICORP SA"},
        "200.32.120.184": {"Buenos Aires, Ciudad Autonoma de Buenos Aires", "AS3549", "Level 3 Parent, LLC"},
        "200.59.236.202": {"Anelo, Neuquen ", "AS27751", "Neunet S.A."},
        "200.16.147.18": {"Buenos Aires, Ciudad Autonoma de Buenos Aires", "AS7049", "Silica Networks Argentina S.A."},
    },
    "am": map[string][]string{
        "31.47.196.211": {"Abovyan, Kotayk", "AS49800", "GNC-Alfa CJSC"},
        "31.47.196.210": {"Abovyan, Kotayk", "AS49800", "GNC-Alfa CJSC"},
        "81.16.8.110": {"Yerevan, Erevan", "AS44395", "Ucom CJSC"},
        "185.8.3.151": {"Abovyan, Kotayk", "AS49800", "GNC-Alfa CJSC"},
        "45.133.105.123": {"Yerevan, Erevan", "AS49800", "GNC-Alfa CJSC"},
    },
    "au": map[string][]string{
        "103.86.96.100": {"Sydney, New South Wales", "AS136787", "TEFINCOM S.A"},
        "61.8.0.113": {"Sydney, New South Wales", "AS1221", "Telstra Corporation Ltd"},
        "103.224.162.40": {"Coomba Park, New South Wales", "AS133324", "Ezi-Web"},
        "192.232.128.21": {"Box Hill, Victoria ", "AS23922", "BOX HILL INSTITUTE"},
        "115.70.249.182": {"Perth, Western Australia ", "AS10143", "Exetel Pty Ltd"},
        "139.130.4.4": {"Adelaide, South Australia", "AS1221", "Telstra Corporation Ltd"},
        "139.134.5.51": {"Sydney, New South Wales", "AS1221", "Telstra Corporation Ltd"},
        "139.134.2.190": {"Sydney, New South Wales", "AS1221", "Telstra Corporation Ltd"},
        "203.2.193.67": {"St Leonards, New South Wales", "AS703", "MCI Communications Services"},
        "203.50.2.71": {"Melbourne, Victoria", "AS1221", "Telstra Corporation Ltd"},
        "110.142.121.50": {"Ramsay, Queensland ", "AS1221", "Telstra Corporation Ltd"},
    },
    "at": map[string][]string{
        "37.235.1.174": {"Vienna, Wien", "AS51453", "ANEXIA Internetdienstleistungs GmbH"},
        "37.235.1.177": {"Vienna, Wien", "AS51453", "ANEXIA Internetdienstleistungs GmbH"},
        "188.21.14.72": {"Vienna, Wien", "AS8447", "A1 Telekom Austria"},
        "193.186.170.50": {"Hagenberg, Oberosterreich", "AS35369", "LINZ STROM GAS"},
        "83.137.41.8": {"Innsbruck, Tirol", "AS31394", "nemox.net Informationstechnologie"},
        "83.137.41.9": {"Innsbruck, Tirol", "AS31394", "nemox.net Informationstechnologie"},
        "185.242.177.7": {"Leonding, Oberosterreich ", "AS35369", "LINZ STROM GAS WAERME GmbH fuer Energiedienstleistungen und Telekommunikation"},
        "194.36.144.87": {"Vienna, Wien", "AS197540", "netcup GmbH"},
        "188.118.227.21": {"Vienna, Wien", "AS8437", "Hutchison Drei Austria"},
        "83.218.176.140": {"Soelden, Tirol", "AS31543", "myNet GmbH"},
    },
    "az": map[string][]string{
        "85.132.85.85": {"Baku, Baki", "AS29049", "Delta Telecom Ltd"},
        "85.132.32.41": {"Baku, Baki", "AS207251", "CASPEL LLC"},
    },
    "bh": map[string][]string{
        "80.95.220.186": {"Umm ash Sha'um, Al Janubiyah", "AS35457", "Etisalcom Bahrain Company W.L.L."},
    },
    "bb": map[string][]string{
        "65.48.140.32": {"Kingstown, Saint George", "AS46408", "Columbus Communication St. Vincent and the Grenadines Ltd."},
        "65.48.140.38": {"Kingstown, Saint George", "AS46408", "Columbus Communication St. Vincent and the Grenadines Ltd."},
        "65.48.140.112": {"Kingstown, Saint George", "AS46408", "Columbus Communication St. Vincent and the Grenadines Ltd."},
        "65.48.140.125": {"Kingstown, Saint George", "AS46408", "Columbus Communication St. Vincent and the Grenadines Ltd."},
        "65.48.140.138": {"Kingstown, Saint George", "AS46408", "Columbus Communication St. Vincent and the Grenadines Ltd."},
        "65.48.140.150": {"Kingstown, Saint George", "AS46408", "Columbus Communication St. Vincent and the Grenadines Ltd."},
        "65.48.140.162": {"Kingstown, Saint George", "AS46408", "Columbus Communication St. Vincent and the Grenadines Ltd."},
        "65.48.140.192": {"Kingstown, Saint George", "AS46408", "Columbus Communication St. Vincent and the Grenadines Ltd."},
        "65.48.140.204": {"Kingstown, Saint George", "AS46408", "Columbus Communication St. Vincent and the Grenadines Ltd."},
        "65.48.140.250": {"Kingstown, Saint George", "AS46408", "Columbus Communication St. Vincent and the Grenadines Ltd."},
        "65.48.141.112": {"Lovell Village, Grenadines", "AS46408", "Columbus Communication St. Vincent and the Grenadines Ltd."},
        "65.48.234.43": {"Kingstown, Saint George", "AS46408", "Columbus Communication St. Vincent and the Grenadines Ltd."},
        "65.48.234.44": {"Kingstown, Saint George", "AS46408", "Columbus Communication St. Vincent and the Grenadines Ltd."},
        "65.48.234.81": {"Kingstown, Saint George", "AS46408", "Columbus Communication St. Vincent and the Grenadines Ltd."},
        "65.48.234.232": {"Kingstown, Saint George", "AS46408", "Columbus Communication St. Vincent and the Grenadines Ltd."},
    },
    "by": map[string][]string{
        "213.184.224.254": {"Druzhba, Horad Minsk", "AS42772", "Unitary enterprise A1"},
        "213.184.225.37": {"Minsk, Horad Minsk", "AS42772", "Unitary enterprise A1"},
    },
    "be": map[string][]string{
        "81.95.125.20": {"Brugge, West-Vlaanderen", "AS42160", "lcp nv"},
        "91.183.238.145": {"Brussels, Brussels Hoofdstedelijk Gewest", "AS5432", "Proximus NV"},
        "194.7.1.4": {"Machelen, Vlaams-Brabant", "AS702", "MCI Communications Services, Inc. d/b/a Verizon Business"},
        "195.35.110.4": {"Brussels, Hoofdstedelijk Gewest", "AS15776", "International Business Machines of Belgium Ltd"},
        "81.82.250.182": {"be Antwerpen, Antwerpen", "AS6848", "Telenet BVBA"},
        "185.92.196.182": {"Waregem, West-Vlaanderen ", "AS200884", "Effix Group"},
        "194.78.185.81": {"be Mons, Hainaut", "AS5432", "Proximus NV"},
        "81.82.196.44": {"Zaventem, Vlaams-Brabant", "AS6848", "Telenet BVBA"},
        "81.82.197.98": {"Zaventem, Vlaams-Brabant", "AS6848", "Telenet BVBA"},
        "81.82.199.111": {"Leuven, Vlaams-Brabant", "AS6848", "Telenet BVBA"},
        "81.83.12.253": {"be Turnhout, Antwerpen", "AS6848", "Telenet BVBA"},
        "81.83.18.23": {"Kortrijk, West-Vlaanderen", "AS6848", "Telenet BVBA"},
        "81.83.18.81": {"Kortrijk, West-Vlaanderen", "AS6848", "Telenet BVBA"},
        "81.83.19.129": {"Gent, Oost-Vlaanderen", "AS6848", "Telenet BVBA"},
        "84.199.232.98": {"Mechelen, Antwerpen", "AS6848", "Telenet BVBA"},
    },
    "bj": map[string][]string{
        "196.192.16.5": {"Abomey-Calavi, Atlantique", "AS28683", "BENIN TELECOMS INFRASTRUCTURES SA"},
    },
    "bt": map[string][]string{
        "103.29.225.241": {"Thimphu, Thimphu", "AS23955", "TashiCell Domestic AS, Thimphu, Bhutan"},
    },
    "bo": map[string][]string{
        "200.105.133.162": {"La Paz, La Paz", "AS26210", "AXS Bolivia S. A."},
        "200.87.195.70": {"La Paz, La Paz", "AS6568", "Entel S.A."},
        "167.157.20.2": {"Cochabamba, Cochabamba", "AS6568", "Entel S.A."},
    },
    "ba": map[string][]string{
        "188.124.210.1": {"Banja Luka, Republika Srpska", "AS198252", "ELTA KABEL d.o.o."},
        "92.36.225.9": {"Gradacac, Federacija Bosne i Hercegovine", "AS9146", "BH Telecom d.d."},
    },
    "bw": map[string][]string{
        "154.70.151.66": {"Mogoditshane, Kweneng", "AS327716", "Microteck Enterprises (Pty) Ltd."},
    },
    "br": map[string][]string{
        "189.125.18.5": {"Cotia, Sao Paulo", "AS3549", "Level 3 Parent, LLC"},
        "177.131.114.86": {"Chapeco, Santa Catarin", "AS262391", "ACESSOLINE TELECOMUNICACOES LTDA"},
        "54.94.175.250": {"Sao Paulo, Sao Paulo", "AS16509", "Amazon.com, Inc."},
        "177.43.35.247": {"Balneario Camboriu, Sa..", "AS18881", "TELEFÔNICA BRASIL S.A"},
        "177.66.203.10": {"Mata de Sao Joao, Bahi", "AS53004", "Downup Telecomunicacoes e servico LTDA"},
        "177.67.81.134": {"Franca, Sao Paul", "AS53013", "W I X NET DO BRASIL LTDA - ME"},
        "177.92.0.90": {"Piraquara, Paran", "AS14868", "COPEL Telecomunicações S.A."},
        "177.135.204.163": {"Lauro de Freitas, Bahi", "AS18881", "TELEFÔNICA BRASIL S.A"},
        "177.159.232.50": {"Brasilia, Distrito Fed..", "AS18881", "TELEFÔNICA BRASIL S.A"},
        "177.159.232.52": {"Brasilia, Distrito Fed..", "AS18881", "TELEFÔNICA BRASIL S.A"},
        "177.159.232.53": {"Brasilia, Distrito Fed..", "AS18881", "TELEFÔNICA BRASIL S.A"},
        "177.184.131.180": {"Sao Bernardo, Maranhao", "AS28368", "SOBRALNET SERVICOS E TELECOMUNICACOES LTDA"},
        "186.194.224.82": {"Tupa, Sao Paul", "AS53143", "R&R PROVEDOR DE INTERNET LTDA"},
        "186.225.194.29": {"Sao Paulo, Sao Paulo", "AS53174", "Pannet Serviços On Line Ltda"},
        "187.32.81.223": {"Alvorada, Rio Grande d..", "AS16735", "ALGAR TELECOM S/A"},
        "187.60.128.69": {"Lavras, Minas Gerais", "AS28152", "Navinet Ltda"},
        "189.4.130.159": {"Santos, Sao Paul", "AS28573", "CLARO S.A."},
        "189.42.239.34": {"Divinopolis, Minas Gerai", "AS4230", "CLARO S.A."},
        "200.99.138.94": {"Sao Paulo, Sao Paulo", "AS10429", "TELEFÔNICA BRASIL S.A"},
        "200.99.138.103": {"Sao Paulo, Sao Paulo", "AS10429", "TELEFÔNICA BRASIL S.A"},
        "200.167.191.114": {"Sinop, Mato Grosso", "AS4230", "CLARO S.A."},
        "200.169.8.1": {"Belo Horizonte, Minas ..", "AS21574", "Century Telecom Ltda"},
        "200.174.105.3": {"Sao Paulo, Sao Paulo", "AS4230", "CLARO S.A."},
        "200.179.97.194": {"Rio de Janeiro, Rio de..", "AS4230", "CLARO S.A."},
        "200.252.235.20": {"Brasilia, Distrito Fed..", "AS4230", "CLARO S.A."},
        "201.45.193.131": {"Horizonte, Ceara", "AS4230", "CLARO S.A."},
        "186.216.63.97": {"Rio Bonito, Rio de Jan..", "AS262663", "METROFLEX TELECOMUNICACOES LTDA"},
        "138.36.1.131": {"Fortaleza, Ceara", "AS264562", "TEX NET SERVIÇOS DE COMUNICAÇÃO EM INFORMATICA LTD"},
        "177.104.127.114": {"Fortaleza, Ceara", "AS263655", "S&T PARTICIPACOES LTDA"},
        "177.37.175.32": {"Joao Pessoa, Paraiba", "AS28126", "BRISANET SERVICOS DE TELECOMUNICACOES LTDA"},
        "138.0.207.117": {"Penapolis, Sao Paulo", "AS264556", "L. Garcia Comunicações ME"},
        "177.43.56.139": {"Diadema, Sao Paulo", "AS18881", "TELEFÔNICA BRASIL S.A"},
        "177.47.128.2": {"Campos, Rio de Janeiro", "AS52993", "Ver Tv Comunicações S/A"},
        "179.127.175.242": {"Lages, Santa Catarin", "AS28343", "Unifique Telecomunicações SA"},
        "187.32.81.194": {"Alvorada, Rio Grande d..", "AS16735", "ALGAR TELECOM S/A"},
        "189.125.73.13": {"Sao Paulo, Sao Paulo", "AS3549", "Level 3 Parent, LLC"},
        "200.150.112.58": {"Apucarana, Paran", "AS14868", "COPEL Telecomunicações S.A."},
        "200.221.11.100": {"Sao Paulo, Sao Paulo", "AS7162", "Universo Online S.A."},
        "200.194.198.76": {"New York City, New Yor", "AS3549", "Level 3 Parent, LLC"},
        "200.221.11.101": {"Sao Paulo, Sao Paulo", "AS7162", "Universo Online S.A."},
        "189.90.241.10": {"Itabira, Minas Gerai", "AS28201", "Companhia Itabirana Telecomunicações Ltda"},
        "201.44.177.131": {"Joinville, Santa Catarin", "AS4230", "CLARO S.A."},
        "201.20.36.29": {"Sao Paulo, Sao Paulo", "AS16397", "EQUINIX BRASIL"},
        "131.221.81.1": {"Sao Paulo, Sao Paulo", "AS4809", "China Telecom Next Generation Carrier Network Who"},
        "179.108.248.9": {"Recife, Pernambuco", "AS263276", "BBG TELECOMLTDA"},
        "131.196.220.10": {"Porto Alegre, Rio Gran..", "AS265985", "MELNET PROVEDOR"},
        "138.219.105.100": {"Porto Alegre, Rio Gran..", "AS263925", "Acem Telecom Ltda"},
        "138.97.84.2": {"Vila Velha, Espirito S..", "AS264138", "INTERLES COMUNICACOES LTDA"},
        "138.97.84.3": {"Vila Velha, Espirito S..", "AS264138", "INTERLES COMUNICACOES LTDA"},
        "164.163.1.90": {"Brasilia, Distrito Fed..", "AS265933", "connectx serviços de telecomunicações ltda"},
        "168.196.78.18": {"Redencao, Ceara", "AS265455", "SKYNET TELECOM EIRELI"},
        "170.239.136.10": {"Natal, Rio Grande do N..", "AS266352", "MUNDO NET"},
        "170.239.144.20": {"Recife, Pernambuco", "AS266361" , "JARBAS PASCHOAL BRAZIL JUNIOR INFORMATICA"},
        "177.102.143.166": {"Sao Paulo, Sao Paulo", "AS27699", "TELEFÔNICA BRASIL S.A"},
        "177.135.239.132": {"Sao Paulo, Sao Paulo", "AS10429", "TELEFÔNICA BRASIL S.A"},
        "177.184.176.5": {"Itamarandiba, Minas Ge..", "AS52923", "Netcar Internet Telec Info e Tecnologia LTDA"},
        "177.200.48.48": {"Rio de Janeiro, Rio de..", "AS52781", "Pertec Servicos de Telecomunicacoes ltda"},
        "177.200.78.209": {"Cajuru, Sao Paul", "AS52783", "SKYNET TELECOMUNICACOES EIRELI"},
        "177.55.32.240": {"Alto Parana, Paran", "AS262482", "HOMENET TELECOMUNICAÇÕES LTDA"},
        "177.75.4.34": {"Brasilia, Distrito Fed..", "AS28178", "Networld Provedor e Servicos de Internet Ltda"},
        "177.87.96.4": {" Natal, Rio Grande do N..", "AS262654", "Governo do Estado do Rio Grande do Norte"},
        "179.181.132.219": {"Aracaju, Sergipe", "AS18881", "TELEFÔNICA BRASIL S.A"},
        "179.191.88.90": {"Sao Paulo, Sao Paulo", "AS17222", "Mundivox LTDA"},
        "179.228.67.140": {"Sao Paulo, Sao Paulo", "AS27699", "TELEFÔNICA BRASIL S.A"},
        "186.225.45.138": {"Teresina, Piau", "AS28368", "SOBRALNET SERVICOS E TELECOMUNICACOES LTDA"},
        "186.248.139.42": {"Belo Horizonte, Minas ..", "AS23106", "AMERICAN TOWER DO BRASIL-COMUNICAÇÂO MULTIMÍDIA LT"},
        "186.251.103.10": {"Ipatinga, Minas Gerais", "AS262828", "Acesse Facil Telecomunicacoes Ltda"},
        "186.251.103.3": {"Ipatinga, Minas Gerais", "AS262828", "Acesse Facil Telecomunicacoes Ltda"},
        "186.251.226.253": {"Atibaia, Sao Paulo", "AS262838", "STARNET TELECOMUNICACOES LTDA"},
        "187.45.113.26": {"Chapeco, Santa Catarin", "AS28146", "MHNET TELECOM"},
        "187.49.127.110": {"Salvador, Bahi", "AS28144", "G3 TELECOM"},
        "187.51.127.93": {"Sao Paulo, Sao Paulo", "AS10429", "TELEFÔNICA BRASIL S.A"},
        "187.72.135.133": {"Sao Paulo, Sao Paulo", "AS16735", "ALGAR TELECOM S/A"},
        "189.126.192.4": {"Sao Paulo, Sao Paulo", "AS28226", "Vogel Soluções em Telecom e Informática S/A"},
        "189.23.31.242": {"Vila Velha, Espirito S..", "AS4230", "CLARO S.A."},
        "189.51.144.23": {"Tupa, Sao Paul", "AS28349", "TVC TUPA EIRELI"},
        "189.8.80.35": {"Sao Paulo, Sao Paulo", "AS28669", "America-NET Ltda."},
        "189.89.61.244": {"Junqueiro, Alagoas", "AS262751", "LINK POINT SERVIÇOS LTDA-ME"},
        "192.141.232.10": {"Padre Bernardo, Goia", "AS267495", "Brasil Central Telecomunicação"},
        "200.143.177.83": {"Sao Paulo, Sao Paulo", "AS16397", "EQUINIX BRASIL"},
        "200.150.83.115": {"Colombo, Paran", "AS14868", "COPEL Telecomunicações S.A."},
        "200.169.96.11": {"Sao Paulo, Sao Paulo", "AS21911", "UOL DIVEO S.A. "},
        "200.178.191.82": {"Rio de Janeiro, Rio de..", "AS4230", "CLARO S.A. "},
        "200.202.233.21": {"Horizonte, Ceara", "AS7738", "Telemar Norte Leste S.A."},
        "200.212.2.125": {"Sao Paulo, Sao Paulo", "AS4230", "CLARO S.A."},
        "200.222.15.35": {"Petropolis, Rio de Jan..", "AS7738", "Telemar Norte Leste S.A."},
        "200.252.235.19": {"Brasilia, Distrito Fed..", "AS4230", "CLARO S.A."},
        "201.28.69.243": {"Sao Paulo, Sao Paulo", "AS10429", "TELEFÔNICA BRASIL S.A"},
        "189.22.227.194": {"Rio de Janeiro, Rio de..", "AS4230", "CLARO S.A."},
        "200.169.88.1": {"Sao Paulo, Sao Paulo", "AS21741", "Visualcorp Holding Ltda"},
        "200.201.191.91": {"Mesquita, Rio de Janeiro", "AS17222", "Mundivox LTDA"},
        "186.193.207.158": {"Sorocaba, Sao Paul", "AS262730", "Byteweb Comunicação Multimídia Ltda."},
        "200.222.51.209": {"Rio de Janeiro, Rio de..", "AS7738", "Telemar Norte Leste S.A."},
        "177.92.1.35": {"Lapa, Parana", "AS14868", "COPEL Telecomunicações S.A."},
        "177.92.1.38": {"apa, Parana", "AS14868", "COPEL Telecomunicações S.A."},
        "200.150.68.126": {"Curitiba, Parana", "AS14868", "COPEL Telecomunicações S.A."},
        "200.150.84.26": {"Cambe, Paran", "AS14868", "COPEL Telecomunicações S.A."},
        "200.195.132.210": {"Curitiba, Parana", "AS14868", "COPEL Telecomunicações S.A."},
        "200.195.136.198": {"Curitiba, Parana", "AS14868", "COPEL Telecomunicações S.A."},
        "200.195.154.122": {"Vitoria, Espirito Sant", "AS14868", "COPEL Telecomunicações S.A."},
        "200.195.185.234": {"Curitiba, Parana", "AS14868", "COPEL Telecomunicações S.A."},
        "189.125.17.210": {"Houston, Texas", "AS3549", "Level 3 Parent, LLC"},
        "189.125.19.198": {"New York City, New Yor", "AS3549", "Level 3 Parent, LLC"},
        "200.194.198.75": {"New York City, New Yor", "AS3549", "Level 3 Parent, LLC"},
        "200.99.138.100": {"Sao Paulo, Sao Paulo", "AS10429", "TELEFÔNICA BRASIL S.A"},
        "179.191.86.162": {"Sao Paulo, Sao Paulo", "AS17222", "Mundivox LTDA"},
        "177.43.249.132": {"Sao Paulo, Sao Paulo", "AS18881", "TELEFÔNICA BRASIL S.A"},
        "200.150.113.147": {"Curitiba, Parana", "AS14868", "COPEL Telecomunicações S.A."},
        "177.69.96.187": {"Uberlandia, Minas Gerais", "AS16735", "ALGAR TELECOM S/A"},
        "187.115.169.30": {"Salvador, Bahi", "AS18881", "TELEFÔNICA BRASIL S.A"},
        "187.33.230.114": {"Joao Pessoa, Paraiba", "AS53087", "TELY Ltda."},
        "189.124.138.68": {"Natal, Rio Grande do N..", "AS28220", "CABO SERVICOS DE TELECOMUNICACOES LTDA"},
        "200.99.138.104": {"Sao Paulo, Sao Paulo", "AS10429", "TELEFÔNICA BRASIL S.A"},
        "200.99.138.13": {"Sao Paulo, Sao Paulo", "AS10429", "TELEFÔNICA BRASIL S.A"},
        "177.204.84.54": {"Sao Paulo, Sao Paulo", "AS18881", "TELEFÔNICA BRASIL S.A"},
        "187.75.155.116": {"Sao Jose dos Campos, S..", "AS27699", "TELEFÔNICA BRASIL S.A"},
        "177.19.217.206": {"Vila Velha, Espirito S..", "AS18881", "TELEFÔNICA BRASIL S.A"},
        "177.130.60.40": {"Santarem, Para", "AS52747", "Wsp Serviços de Telecomunicações Ltda"},
        "189.55.193.173": {"Sao Paulo, Sao Paulo", "AS28573", "CLARO S.A."},
        "201.48.242.193": {"Uberlandia, Minas Gerais", "AS16735", "ALGAR TELECOM S/A"},
        "179.185.88.86": {"Campo Grande, Mato Gro..", "AS18881", "TELEFÔNICA BRASIL S.A"},
        "200.161.143.52": {"Piracicaba, Sao Paul", "AS27699", "TELEFÔNICA BRASIL S.A"},
        "177.92.19.182": {"Curitiba, Parana", "AS14868", "COPEL Telecomunicações S.A."},
        "168.196.78.22": {"Redencao, Ceara", "AS265455", "SKYNET TELECOM EIRELI"},
        "168.228.148.43": {"Cavalcante, Goias", "AS264953", "INTEGRATO TELECOMUNICAÇÕES LTDA - ME"},
        "177.124.247.2": {"Rio de Janeiro, Rio de..", "AS17222", "Mundivox LTDA"},
        "177.155.135.81": {"Cacador, Santa Catarin", "AS53062", "GGNET TELECOMUNICAÇÕES LTDA"},
        "177.69.240.252": {"Blumenau, Santa Catarina", "AS16735", "ALGAR TELECOM S/A"},
        "177.93.250.3": {"Jacobina, Bahia", "AS52995", "TEN INTERNET Ltda"},
        "186.215.192.243": {"Pompeia, Sao Paulo", "AS18881", "TELEFÔNICA BRASIL S.A"},
        "191.253.65.194": {"Sao Luis, Maranhao", "AS263528", "VIACOM NEXT GENERATION COMUNICACAO LTDA"},
        "200.220.192.88": {"Rio de Janeiro, Rio de..", "AS262589", "INTERNEXA BRASIL OPERADORA DE TELECOMUNICACOES S.A"},
        "45.225.123.34": {"Paulo Afonso, Bahi", "AS266935", "CENTROSULNET INFORMATICA EIRELI"},
        "45.225.123.88": {"Paulo Afonso, Bahi", "AS266935", "CENTROSULNET INFORMATICA EIRELI"},
        "177.20.178.12": {"Piracicaba, Sao Paul", "AS263035", "PORTAL QUEOPS TELECOMUNICAÇÕES E SERVIÇOS"},
    },
    "io": map[string][]string{
        "202.44.113.14": {"Diego Garcia, British Indian Ocean Territory", "AS17458", "Sure (Diego Garcia) Limited"},
    },
    "bn": map[string][]string{
        "202.152.77.212": {"Bandar Seri Begawan, Brunei-Muara", "AS10101", "UNN-BN"},
    },
    "bg": map[string][]string{
        "46.35.180.2": {"Levski, Pleven ", "AS58079", "Skynet Ltd"},
        "85.118.192.3": {"Sofia, Sofia (stolitsa)", "AS29244", "TELENOR BULGARIA EAD"},
        "95.158.129.2": {"Sofia, Sofia (stolitsa)", "AS41313", "NOVATEL EOOD"},
        "212.73.140.66": {"Sofia, Sofia (stolitsa)", "AS34224", "Neterra Ltd."},
        "46.10.205.252": {"Sofia, Sofia (stolitsa)", "AS8866", "Bulgarian Telecommunications Company Plc."},
        "194.141.12.1": {"Sofia, Sofia (stolitsa)", "AS6802", "Bulgarian Research and Education Network Association (BREN)"},
        "212.91.171.146": {"Sofia, Sofia (stolitsa)", "AS8717", "A1 Bulgaria EAD"},
        "93.123.112.99": {"Svoge, Sofia ", "AS43561", "NET1 Ltd."},
        "195.24.36.55": {"Sofia, Sofia (stolitsa)", "AS8717", "A1 Bulgaria EAD"},
        "84.54.131.65": {"Burgas, Burgas ", "AS29084", "Comnet Bulgaria Holding"},
        "80.78.237.33": {"Satovcha, Blagoevgrad", "AS39184", "UltraNET Ltd"},
        "89.106.109.235": {"Gabrovo, Gabrovo ", "AS13306", "Unics EOOD"},
        "80.78.237.4": {"Satovcha, Blagoevgrad", "AS39184", "UltraNET Ltd "},
        "195.234.239.130": {"Sofia, Sofia (stolitsa)", "AS13236", "DATACOM LTD"},
        "95.87.252.178": {"Sofia, Sofia (stolitsa)", "AS43561", "NET1 Ltd."},
        "195.110.24.248": {"Sofia, Sofia (stolitsa)", "AS42191", "State Fund Agriculture"},
        "91.215.219.133": {"Plovdiv, Plovdiv ", "AS49699", "Internet Corporated Networks Ltd."},
    },
    "bf": map[string][]string{
        "196.28.245.26": {"Ouagadougou, Kadiogo", "AS25543", "ONATEL (Office National des Telecommunications, PTT)"},
    },
}

type ServersInfo struct {
    sync.RWMutex
    inner             []*ServerInfo
    registeredServers []RegisteredServer
    lbStrategy        LBStrategy
    lbStrategyStr     string
    lbEstimator       bool
    prevCandidate     int
}

func NewServersInfo() ServersInfo {
    return ServersInfo{lbStrategy: DefaultLBStrategy, lbEstimator: true, registeredServers: make([]RegisteredServer, 0)}
}

func (serversInfo *ServersInfo) registerServer(name string, stamp stamps.ServerStamp) {
    newRegisteredServer := RegisteredServer{name: name, stamp: stamp}
    serversInfo.Lock()
    defer serversInfo.Unlock()
    for i, oldRegisteredServer := range serversInfo.registeredServers {
        if oldRegisteredServer.name == name {
            serversInfo.registeredServers[i] = newRegisteredServer
            return
        }
    }
    serversInfo.registeredServers = append(serversInfo.registeredServers, newRegisteredServer)
}

func (serversInfo *ServersInfo) refreshServer(proxy *Proxy, name string, stamp stamps.ServerStamp) error {
    serversInfo.RLock()
    isNew := true
    for _, oldServer := range serversInfo.inner {
        if oldServer.Name == name {
            isNew = false
            break
        }
    }
    serversInfo.RUnlock()
    newServer, err := fetchServerInfo(proxy, name, stamp, isNew)
    if err != nil {
        return err
    }
    if name != newServer.Name {
        dlog.Fatalf("[%s] != [%s]", name, newServer.Name)
    }
    newServer.rtt = ewma.NewMovingAverage(RTTEwmaDecay)
    newServer.rtt.Set(float64(newServer.initialRtt))
    isNew = true
    serversInfo.Lock()
    for i, oldServer := range serversInfo.inner {
        if oldServer.Name == name {
            serversInfo.inner[i] = &newServer
            isNew = false
            break
        }
    }
    if isNew {
        serversInfo.inner = append(serversInfo.inner, &newServer)
        serversInfo.registeredServers = append(serversInfo.registeredServers, RegisteredServer{name: name, stamp: stamp})
    }
    serversInfo.Unlock()
    return nil
}

func (serversInfo *ServersInfo) refresh(proxy *Proxy) (int, error) {
    dlog.Debug("Refreshing certificates")
    serversInfo.RLock()
    registeredServers := serversInfo.registeredServers
    serversInfo.RUnlock()
    liveServers := 0
    var err error
    for _, registeredServer := range registeredServers {
        if err = serversInfo.refreshServer(proxy, registeredServer.name, registeredServer.stamp); err == nil {
            liveServers++
        }
    }
    serversInfo.Lock()
    sort.SliceStable(serversInfo.inner, func(i, j int) bool {
        /**
         * Sort by name of servers provided in config file rather than RTTs.
         * This ensures that the mapping of domain names to resolvers 
         * will be consistent, even when the certificates are refreshed.
         * Note that the LB estimator needs to be disabled as well to ensure 
         * that the order doesn't change when latencies are periodically 
         * re-measured.
         */
        // return serversInfo.inner[i].initialRtt < serversInfo.inner[j].initialRtt
        return serversInfo.inner[i].Name < serversInfo.inner[j].Name
    })
    inner := serversInfo.inner
    innerLen := len(inner)
    if innerLen > 1 {
        dlog.Notice("Sorted latencies:")
        for i := 0; i < innerLen; i++ {
            dlog.Noticef("- %5dms %s", inner[i].initialRtt, inner[i].Name)
        }
    }
    if innerLen > 0 {
        dlog.Noticef("Server with the lowest initial latency: %s (rtt: %dms)", inner[0].Name, inner[0].initialRtt)
    }
    serversInfo.Unlock()
    return liveServers, err
}

func (serversInfo *ServersInfo) estimatorUpdate() {
    // serversInfo.RWMutex is assumed to be Locked
    candidate := rand.Intn(len(serversInfo.inner))
    if candidate == 0 {
        return
    }
    candidateRtt, currentBestRtt := serversInfo.inner[candidate].rtt.Value(), serversInfo.inner[0].rtt.Value()
    if currentBestRtt < 0 {
        currentBestRtt = candidateRtt
        serversInfo.inner[0].rtt.Set(currentBestRtt)
    }
    partialSort := false
    if candidateRtt < currentBestRtt {
        serversInfo.inner[candidate], serversInfo.inner[0] = serversInfo.inner[0], serversInfo.inner[candidate]
        partialSort = true
        dlog.Debugf("New preferred candidate: %v (rtt: %d vs previous: %d)", serversInfo.inner[0].Name, int(candidateRtt), int(currentBestRtt))
    } else if candidateRtt > 0 && candidateRtt >= currentBestRtt*4.0 {
        if time.Since(serversInfo.inner[candidate].lastActionTS) > time.Duration(1*time.Minute) {
            serversInfo.inner[candidate].rtt.Add(MinF(MaxF(candidateRtt/2.0, currentBestRtt*2.0), candidateRtt))
            dlog.Debugf("Giving a new chance to candidate [%s], lowering its RTT from %d to %d (best: %d)", serversInfo.inner[candidate].Name, int(candidateRtt), int(serversInfo.inner[candidate].rtt.Value()), int(currentBestRtt))
            partialSort = true
        }
    }
    if partialSort {
        serversCount := len(serversInfo.inner)
        for i := 1; i < serversCount; i++ {
            if serversInfo.inner[i-1].rtt.Value() > serversInfo.inner[i].rtt.Value() {
                serversInfo.inner[i-1], serversInfo.inner[i] = serversInfo.inner[i], serversInfo.inner[i-1]
            }
        }
    }
}

func (serversInfo *ServersInfo) getOne(qName string) *ServerInfo {
    serversInfo.Lock()
    serversCount := len(serversInfo.inner)
    if serversCount <= 0 {
        serversInfo.Unlock()
        return nil
    }
    if serversInfo.lbEstimator {
        serversInfo.estimatorUpdate()
    }
    candidate := 0
    switch serversInfo.lbStrategyStr {
        case "rr":
            candidate = (serversInfo.prevCandidate + 1) % serversCount
        case "hash":
            h := fnv.New32a()
            sld, err := parseSLD(qName)
            if err != nil {
                serversInfo.Unlock()
                return nil
            }
            h.Write([]byte(sld))
            index := h.Sum32()
            candidate = int(index % uint32(serversCount))
        default:
            candidate = serversInfo.lbStrategy.getCandidate(serversCount)
    }
    // Compare addr. of candidate with denylist addresses
    if serversInfo.lbStrategyStr == "la" {
        la_flag := 0
        changed_flag := 0
        candidate = serversInfo.lbStrategy.getCandidate(serversCount)
        serversInfo.prevCandidate = candidate
        serverInfo := serversInfo.inner[candidate]
        for la_flag != 1 { // Scuffed flag for while loop
            changed_flag = 0 // Reset
            for k, v := range denylist { // Iterate over "first key" layer of map
                _ = k
                for key, val := range v { // Iterate over all IP addr. strings of DNS
                    _ = val
                    if reflect.DeepEqual((*serverInfo).TCPAddr.IP, net.ParseIP(key)) { // On match, reset candidate and serverInfo, continue to double check new assignment
                        candidate = serversInfo.lbStrategy.getCandidate(serversCount)
                        serversInfo.prevCandidate = candidate
                        serverInfo = serversInfo.inner[candidate]
                        changed_flag = 1
                        break
                    }
                }
            }
            if changed_flag == 0 {
                la_flag = 1 // Set flag to exit while loop if if conditional not entered, candidate not re-assigned
            }
        }
    }
    serversInfo.prevCandidate = candidate
    serverInfo := serversInfo.inner[candidate]
    dlog.Debugf("Using candidate [%s] RTT: %d", (*serverInfo).Name, int((*serverInfo).rtt.Value()))
    serversInfo.Unlock()

    return serverInfo
}

func fetchServerInfo(proxy *Proxy, name string, stamp stamps.ServerStamp, isNew bool) (ServerInfo, error) {
    if stamp.Proto == stamps.StampProtoTypeDNSCrypt {
        return fetchDNSCryptServerInfo(proxy, name, stamp, isNew)
    } else if stamp.Proto == stamps.StampProtoTypeDoH {
        return fetchDoHServerInfo(proxy, name, stamp, isNew)
    }
    return ServerInfo{}, errors.New("Unsupported protocol")
}

func route(proxy *Proxy, name string) (*net.UDPAddr, *net.TCPAddr, error) {
    routes := proxy.routes
    if routes == nil {
        return nil, nil, nil
    }
    relayNames, ok := (*routes)[name]
    if !ok {
        relayNames, ok = (*routes)["*"]
    }
    if !ok {
        return nil, nil, nil
    }
    var relayName string
    if len(relayNames) > 0 {
        candidate := rand.Intn(len(relayNames))
        relayName = relayNames[candidate]
    }
    var relayCandidateStamp *stamps.ServerStamp
    if len(relayName) == 0 {
        return nil, nil, fmt.Errorf("Route declared for [%v] but an empty relay list", name)
    } else if relayStamp, err := stamps.NewServerStampFromString(relayName); err == nil {
        relayCandidateStamp = &relayStamp
    } else if _, err := net.ResolveUDPAddr("udp", relayName); err == nil {
        relayCandidateStamp = &stamps.ServerStamp{
            ServerAddrStr: relayName,
            Proto:         stamps.StampProtoTypeDNSCryptRelay,
        }
    } else {
        for _, registeredServer := range proxy.registeredRelays {
            if registeredServer.name == relayName {
                relayCandidateStamp = &registeredServer.stamp
                break
            }
        }
        for _, registeredServer := range proxy.registeredServers {
            if registeredServer.name == relayName {
                relayCandidateStamp = &registeredServer.stamp
                break
            }
        }
    }
    if relayCandidateStamp == nil {
        return nil, nil, fmt.Errorf("Undefined relay [%v] for server [%v]", relayName, name)
    }
    if relayCandidateStamp.Proto == stamps.StampProtoTypeDNSCrypt ||
        relayCandidateStamp.Proto == stamps.StampProtoTypeDNSCryptRelay {
        relayUDPAddr, err := net.ResolveUDPAddr("udp", relayCandidateStamp.ServerAddrStr)
        if err != nil {
            return nil, nil, err
        }
        relayTCPAddr, err := net.ResolveTCPAddr("tcp", relayCandidateStamp.ServerAddrStr)
        if err != nil {
            return nil, nil, err
        }
        return relayUDPAddr, relayTCPAddr, nil
    }
    return nil, nil, fmt.Errorf("Invalid relay [%v] for server [%v]", relayName, name)
}

func fetchDNSCryptServerInfo(proxy *Proxy, name string, stamp stamps.ServerStamp, isNew bool) (ServerInfo, error) {
    if len(stamp.ServerPk) != ed25519.PublicKeySize {
        serverPk, err := hex.DecodeString(strings.Replace(string(stamp.ServerPk), ":", "", -1))
        if err != nil || len(serverPk) != ed25519.PublicKeySize {
            dlog.Fatalf("Unsupported public key for [%s]: [%s]", name, stamp.ServerPk)
        }
        dlog.Warnf("Public key [%s] shouldn't be hex-encoded any more", string(stamp.ServerPk))
        stamp.ServerPk = serverPk
    }
    knownBugs := ServerBugs{}
    for _, buggyServerName := range proxy.serversBlockingFragments {
        if buggyServerName == name {
            knownBugs.fragmentsBlocked = true
            dlog.Infof("Known bug in [%v]: fragmented questions over UDP are blocked", name)
            break
        }
    }
    relayUDPAddr, relayTCPAddr, err := route(proxy, name)
    if err != nil {
        return ServerInfo{}, err
    }
    certInfo, rtt, fragmentsBlocked, err := FetchCurrentDNSCryptCert(proxy, &name, proxy.mainProto, stamp.ServerPk, stamp.ServerAddrStr, stamp.ProviderName, isNew, relayUDPAddr, relayTCPAddr, knownBugs)
    if !knownBugs.fragmentsBlocked && fragmentsBlocked {
        dlog.Debugf("[%v] drops fragmented queries", name)
        knownBugs.fragmentsBlocked = true
    }
    if knownBugs.fragmentsBlocked && (relayUDPAddr != nil || relayTCPAddr != nil) {
        relayTCPAddr, relayUDPAddr = nil, nil
        if proxy.skipAnonIncompatbibleResolvers {
            dlog.Infof("[%v] is incompatible with anonymization, it will be ignored", name)
            return ServerInfo{}, errors.New("Resolver is incompatible with anonymization")
        }
        dlog.Warnf("[%v] is incompatible with anonymization", name)
    }
    if err != nil {
        return ServerInfo{}, err
    }
    remoteUDPAddr, err := net.ResolveUDPAddr("udp", stamp.ServerAddrStr)
    if err != nil {
        return ServerInfo{}, err
    }
    remoteTCPAddr, err := net.ResolveTCPAddr("tcp", stamp.ServerAddrStr)
    if err != nil {
        return ServerInfo{}, err
    }
    return ServerInfo{
        Proto:              stamps.StampProtoTypeDNSCrypt,
        MagicQuery:         certInfo.MagicQuery,
        ServerPk:           certInfo.ServerPk,
        SharedKey:          certInfo.SharedKey,
        CryptoConstruction: certInfo.CryptoConstruction,
        Name:               name,
        Timeout:            proxy.timeout,
        UDPAddr:            remoteUDPAddr,
        TCPAddr:            remoteTCPAddr,
        RelayUDPAddr:       relayUDPAddr,
        RelayTCPAddr:       relayTCPAddr,
        initialRtt:         rtt,
        knownBugs:          knownBugs,
    }, nil
}

func dohTestPacket(msgID uint16) []byte {
    msg := dns.Msg{}
    msg.SetQuestion(".", dns.TypeNS)
    msg.Id = msgID
    msg.MsgHdr.RecursionDesired = true
    msg.SetEdns0(uint16(MaxDNSPacketSize), false)
    ext := new(dns.EDNS0_PADDING)
    ext.Padding = make([]byte, 16)
    crypto_rand.Read(ext.Padding)
    edns0 := msg.IsEdns0()
    edns0.Option = append(edns0.Option, ext)
    body, err := msg.Pack()
    if err != nil {
        dlog.Fatal(err)
    }
    return body
}

func dohNXTestPacket(msgID uint16) []byte {
    msg := dns.Msg{}
    qName := make([]byte, 16)
    charset := "abcdefghijklmnopqrstuvwxyz"
    for i := range qName {
        qName[i] = charset[rand.Intn(len(charset))]
    }
    msg.SetQuestion(string(qName)+".test.dnscrypt.", dns.TypeNS)
    msg.Id = msgID
    msg.MsgHdr.RecursionDesired = true
    msg.SetEdns0(uint16(MaxDNSPacketSize), false)
    ext := new(dns.EDNS0_PADDING)
    ext.Padding = make([]byte, 16)
    crypto_rand.Read(ext.Padding)
    edns0 := msg.IsEdns0()
    edns0.Option = append(edns0.Option, ext)
    body, err := msg.Pack()
    if err != nil {
        dlog.Fatal(err)
    }
    return body
}

func fetchDoHServerInfo(proxy *Proxy, name string, stamp stamps.ServerStamp, isNew bool) (ServerInfo, error) {
    // If an IP has been provided, use it forever.
    // Or else, if the fallback server and the DoH server are operated
    // by the same entity, it could provide a unique IPv6 for each client
    // in order to fingerprint clients across multiple IP addresses.
    if len(stamp.ServerAddrStr) > 0 {
        ipOnly, _ := ExtractHostAndPort(stamp.ServerAddrStr, -1)
        if ip := ParseIP(ipOnly); ip != nil {
            proxy.xTransport.saveCachedIP(stamp.ProviderName, ip, -1*time.Second)
        }
    }
    url := &url.URL{
        Scheme: "https",
        Host:   stamp.ProviderName,
        Path:   stamp.Path,
    }
    body := dohTestPacket(0xcafe)
    dohClientCreds, ok := (*proxy.dohCreds)[name]
    if !ok {
        dohClientCreds, ok = (*proxy.dohCreds)["*"]
    }
    if ok {
        dlog.Noticef("Enabling TLS authentication for [%s]", name)
        proxy.xTransport.tlsClientCreds = dohClientCreds
        proxy.xTransport.rebuildTransport()
    }
    useGet := false
    if _, _, _, err := proxy.xTransport.DoHQuery(useGet, url, body, proxy.timeout); err != nil {
        useGet = true
        if _, _, _, err := proxy.xTransport.DoHQuery(useGet, url, body, proxy.timeout); err != nil {
            return ServerInfo{}, err
        }
        dlog.Debugf("Server [%s] doesn't appear to support POST; falling back to GET requests", name)
    }
    body = dohNXTestPacket(0xcafe)
    serverResponse, tls, rtt, err := proxy.xTransport.DoHQuery(useGet, url, body, proxy.timeout)
    if err != nil {
        dlog.Infof("[%s] [%s]: %v", name, url, err)
        return ServerInfo{}, err
    }
    if tls == nil || !tls.HandshakeComplete {
        return ServerInfo{}, errors.New("TLS handshake failed")
    }
    msg := dns.Msg{}
    if err := msg.Unpack(serverResponse); err != nil {
        dlog.Warnf("[%s]: %v", name, err)
        return ServerInfo{}, err
    }
    if msg.Rcode != dns.RcodeNameError {
        dlog.Criticalf("[%s] may be a lying resolver", name)
    }
    protocol := tls.NegotiatedProtocol
    if len(protocol) == 0 {
        protocol = "h1"
        dlog.Warnf("[%s] does not support HTTP/2", name)
    }
    dlog.Infof("[%s] TLS version: %x - Protocol: %v - Cipher suite: %v", name, tls.Version, protocol, tls.CipherSuite)
    showCerts := proxy.showCerts
    found := false
    var wantedHash [32]byte
    for _, cert := range tls.PeerCertificates {
        h := sha256.Sum256(cert.RawTBSCertificate)
        if showCerts {
            dlog.Noticef("Advertised cert: [%s] [%x]", cert.Subject, h)
        } else {
            dlog.Debugf("Advertised cert: [%s] [%x]", cert.Subject, h)
        }
        for _, hash := range stamp.Hashes {
            if len(hash) == len(wantedHash) {
                copy(wantedHash[:], hash)
                if h == wantedHash {
                    found = true
                    break
                }
            }
        }
        if found {
            break
        }
    }
    if !found && len(stamp.Hashes) > 0 {
        dlog.Criticalf("[%s] Certificate hash [%x] not found", name, wantedHash)
        return ServerInfo{}, fmt.Errorf("Certificate hash not found")
    }
    respBody := serverResponse
    if len(respBody) < MinDNSPacketSize || len(respBody) > MaxDNSPacketSize ||
        respBody[0] != 0xca || respBody[1] != 0xfe || respBody[4] != 0x00 || respBody[5] != 0x01 {
        dlog.Info("Webserver returned an unexpected response")
        return ServerInfo{}, errors.New("Webserver returned an unexpected response")
    }
    xrtt := int(rtt.Nanoseconds() / 1000000)
    if isNew {
        dlog.Noticef("[%s] OK (DoH) - rtt: %dms", name, xrtt)
    } else {
        dlog.Infof("[%s] OK (DoH) - rtt: %dms", name, xrtt)
    }
    return ServerInfo{
        Proto:      stamps.StampProtoTypeDoH,
        Name:       name,
        Timeout:    proxy.timeout,
        URL:        url,
        HostName:   stamp.ProviderName,
        initialRtt: xrtt,
        useGet:     useGet,
    }, nil
}

func (serverInfo *ServerInfo) noticeFailure(proxy *Proxy) {
    proxy.serversInfo.Lock()
    serverInfo.rtt.Add(float64(proxy.timeout.Nanoseconds() / 1000000))
    proxy.serversInfo.Unlock()
}

func (serverInfo *ServerInfo) noticeBegin(proxy *Proxy) {
    proxy.serversInfo.Lock()
    serverInfo.lastActionTS = time.Now()
    proxy.serversInfo.Unlock()
}

func (serverInfo *ServerInfo) noticeSuccess(proxy *Proxy) {
    now := time.Now()
    proxy.serversInfo.Lock()
    elapsed := now.Sub(serverInfo.lastActionTS)
    elapsedMs := elapsed.Nanoseconds() / 1000000
    if elapsedMs > 0 && elapsed < proxy.timeout {
        serverInfo.rtt.Add(float64(elapsedMs))
    }
    proxy.serversInfo.Unlock()
}

func parseSLD(qName string) (string, error) {
    // TOOD: Figure out how we handle ccTLDs that use two labels, e.g. .co.uk
    labels := dns.SplitDomainName(qName)
    if len(labels) < 2 {
        return "", fmt.Errorf("Couldn't parse second-level domain for %v: not enough labels", qName)
    }
    sld := labels[len(labels)-2] + "." + labels[len(labels)-1]
    return sld, nil
}
