package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type StationTracking struct {
	Count			int
	SignalSum		int
	MinSignal		int8
	MaxSignal		int8
	LastSeenSignal	int8
	FirstSeen		int64
	LastSeen		int64
}

type StationReport struct {
	Mac				string	`json:"mac"`
	Count			int		`json:"count"`
	MinSignal		int8	`json:"min_signal"`
	MaxSignal		int8	`json:"max_signal"`
	AvgSignal		int8	`json:"avg_signal"`
	LastSeenSignal	int8	`json:"last_seen_signal"`
	FirstSeen		int64	`json:"first_seen"`
	LastSeen		int64	`json:"last_seen"`
	Associated		bool	`json:"associated"`
}

type PresenceReport struct {
	NetworkId		int				`json:"network_id"`
	NodeMac			string			`json:"node_mac"`
	Version			int				`json:"version"`
	ProbeRequests	[]StationReport	`json:"probe_requests"`
}

var detections map[string]*StationTracking

func sendPresenceReport(report *PresenceReport) {
	url := os.Getenv("REPORTING_URL")
	if url == "" {
		panic("REPORTING_URL not specified")
	}

	jsonReport, _ := json.Marshal(report)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonReport))
	if err != nil {
		panic(err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Optionally, if SIGNING_KEY is set, compute an HMAC signature and add it
	// to the HTTP header "Signature".
	key, ok := os.LookupEnv("SIGNING_KEY")
	if ok {
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write([]byte(jsonReport))
		sum := base64.URLEncoding.EncodeToString(mac.Sum(nil))
		req.Header.Set("Signature", sum)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()
}

func getHardwareAddr(ifname string) (net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(ifname)
	if err == nil {
		return iface.HardwareAddr, nil
	} else {
		return net.HardwareAddr{0, 0, 0, 0, 0, 0}, err
	}
}

func makePresenceReport() *PresenceReport {
	networkId, _ := strconv.Atoi(os.Getenv("NETWORK_ID"))
	nodeMAC, _ := getHardwareAddr("mon0")

	presenceReport := &PresenceReport{
		NetworkId: networkId,
		NodeMac: nodeMAC.String(),
		Version: 1,
		ProbeRequests: make([]StationReport, 0),
	}

	for source, tracking := range detections {
		stationReport := StationReport{
			Mac: source,
			Count: tracking.Count,
			MinSignal: tracking.MinSignal,
			MaxSignal: tracking.MaxSignal,
			AvgSignal: int8(tracking.SignalSum / tracking.Count),
			LastSeenSignal: tracking.LastSeenSignal,
			FirstSeen: tracking.FirstSeen,
			LastSeen: tracking.LastSeen,
		}

		presenceReport.ProbeRequests = append(presenceReport.ProbeRequests, stationReport)
	}

	return presenceReport
}

func handleFrame(frame gopacket.Packet) {
	radioTapLayer := frame.Layer(layers.LayerTypeRadioTap)
	if radioTapLayer == nil {
		return
	}
	radioTap, _ := radioTapLayer.(*layers.RadioTap)

	dot11Layer := frame.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return
	}
	dot11, _ := dot11Layer.(*layers.Dot11)

	signal := radioTap.DBMAntennaSignal
	if signal >= 0 {
		// Ignore signal strengths that seem invalid.  This occurs somewhat
		// often, but I am not sure what it means.
		return
	}

	if dot11.Type == layers.Dot11TypeMgmtProbeReq || dot11.Flags.ToDS() {
		source := dot11.Address2.String()

		// If this is the first time seeing the station,
		// initialize tracking state.
		if _, ok := detections[source]; !ok {
			detections[source] = &StationTracking{
				FirstSeen: time.Now().Unix(),
				MinSignal: signal,
				MaxSignal: signal,
			}
		}

		tracking := detections[source]
		tracking.Count += 1
		tracking.SignalSum += int(signal)
		if signal < tracking.MinSignal {
			tracking.MinSignal = signal
		}
		if signal > tracking.MaxSignal {
			tracking.MaxSignal = signal
		}
		tracking.LastSeenSignal = signal
		tracking.LastSeen = time.Now().Unix()
	}
}

func sendPeriodicReports() {
	// Read reporting interval from environment variable.
	// Default to 30 seconds if not set appropriately.
	interval, _ := strconv.Atoi(os.Getenv("REPORTING_INTERVAL"))
	if interval == 0 {
		interval = 30
	}

	for {
		time.Sleep(time.Duration(interval) * time.Second)

		report := makePresenceReport()
		sendPresenceReport(report)
		fmt.Println(report)
	}
}

func main() {
	detections = make(map[string]*StationTracking)

	go sendPeriodicReports()

	handle, err := pcap.OpenLive("mon0", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for frame := range packetSource.Packets() {
		handleFrame(frame)
	}
}
