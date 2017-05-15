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
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type StationStatus struct {
	IdlePeriods		int
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

var detections map[string]*StationStatus

func (status *StationStatus) IsIdle() bool {
	return (status.IdlePeriods > 0)
}

func (status *StationStatus) Reset() {
	if status.Count > 1 {
		status.Count = 1

		status.SignalSum = int(status.LastSeenSignal)
		status.MinSignal = status.LastSeenSignal
		status.MaxSignal = status.LastSeenSignal
	}

	status.IdlePeriods++
}

func (status *StationStatus) Update(signal int8) {
	status.IdlePeriods = 0

	status.Count += 1

	status.SignalSum += int(signal)
	if signal < status.MinSignal {
		status.MinSignal = signal
	}
	if signal > status.MaxSignal {
		status.MaxSignal = signal
	}
	status.LastSeenSignal = signal

	status.LastSeen = time.Now().Unix()
}

func sendPresenceReport(report *PresenceReport) {
	url := os.Getenv("REPORTING_URL")
	if url == "" {
		panic("REPORTING_URL not specified")
	}

	jsonReport, _ := json.Marshal(report)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonReport))
	if err != nil {
		fmt.Println(err)
		return
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
		fmt.Println(err)
		return
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

	for source, status := range detections {
		if status.IsIdle() {
			delete(detections, source)
			continue
		}

		stationReport := StationReport{
			Mac: source,
			Count: status.Count,
			MinSignal: status.MinSignal,
			MaxSignal: status.MaxSignal,
			AvgSignal: int8(status.SignalSum / status.Count),
			LastSeenSignal: status.LastSeenSignal,
			FirstSeen: status.FirstSeen,
			LastSeen: status.LastSeen,
		}

		presenceReport.ProbeRequests = append(presenceReport.ProbeRequests, stationReport)

		status.Reset()
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
		// initialize status.
		if _, ok := detections[source]; !ok {
			detections[source] = &StationStatus{
				FirstSeen: time.Now().Unix(),
				MinSignal: signal,
				MaxSignal: signal,
			}
		}

		status := detections[source]
		status.Update(signal)
	}
}

func HopChannels(channels []string) {
	ticker := time.NewTicker(100 * time.Millisecond)

	var i int = 0
	for _ = range ticker.C {
		cmd := exec.Command("iw", "dev", "mon0", "set", "channel", channels[i])
		err := cmd.Start()
		if err != nil {
			fmt.Println(err)
			continue
		}
		err = cmd.Wait()
		if err != nil {
			fmt.Println(err)
			continue
		}

		i = (i + 1) % len(channels)
	}
}

func main() {
	// Read reporting interval from environment variable.
	// Default to 30 seconds if not set appropriately.
	interval, _ := strconv.Atoi(os.Getenv("REPORTING_INTERVAL"))
	if interval == 0 {
		interval = 30
	}

	// If configured with a list of channels, start a goroutine to do the
	// channel hopping.
	scanString := os.Getenv("SCAN_CHANNELS")
	if scanString != "" {
		channels := strings.Split(scanString, ",")
		go HopChannels(channels)
	}

	detections = make(map[string]*StationStatus)

	handle, err := pcap.OpenLive("mon0", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	source := packetSource.Packets()
	ticker := time.NewTicker(time.Duration(interval) * time.Second)

	// Main loop: handle incoming frames and send a presence report every time
	// the ticker fires.
	for {
		select {
		case frame := <-source:
			handleFrame(frame)
		case <-ticker.C:
			report := makePresenceReport()
			sendPresenceReport(report)
			fmt.Printf("Reported %d devices.\n", len(report.ProbeRequests))
		}
	}
}
