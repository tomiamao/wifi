//go:build linux
// +build linux

package wifi

import (
	"context"
	"net"
	"time"

	"github.com/mdlayher/genetlink"
	"golang.org/x/sys/unix"
)

// A Client is a type which can access WiFi device actions and statistics
// using operating system-specific operations.
type Client struct {
	c *client
}

// New creates a new Client.
func New() (*Client, error) {
	c, err := newClient()
	if err != nil {
		return nil, err
	}

	return &Client{
		c: c,
	}, nil
}

// Close releases resources used by a Client.
func (c *Client) Close() error {
	return c.c.Close()
}

// Connect starts connecting the interface to the specified ssid.
func (c *Client) Connect(ifi *Interface, ssid string) error {
	return c.c.Connect(ifi, ssid)
}

// Dissconnect disconnects the interface.
func (c *Client) Disconnect(ifi *Interface) error {
	return c.c.Disconnect(ifi)
}

// Connect starts connecting the interface to the specified ssid using WPA.
func (c *Client) ConnectWPAPSK(ifi *Interface, ssid, psk string) error {
	return c.c.ConnectWPAPSK(ifi, ssid, psk)
}

// Interfaces returns a list of the system's WiFi network interfaces.
func (c *Client) Interfaces() ([]*Interface, error) {
	return c.c.Interfaces()
}

// BSS retrieves the BSS associated with a WiFi interface.
func (c *Client) BSS(ifi *Interface) (*BSS, error) {
	return c.c.BSS(ifi)
}

// StationInfo retrieves all station statistics about a WiFi interface.
//
// Since v0.2.0: if there are no stations, an empty slice is returned instead
// of an error.
func (c *Client) StationInfo(ifi *Interface) ([]*StationInfo, error) {
	return c.c.StationInfo(ifi)
}

// SetDeadline sets the read and write deadlines associated with the connection.
func (c *Client) SetDeadline(t time.Time) error {
	return c.c.SetDeadline(t)
}

// SetReadDeadline sets the read deadline associated with the connection.
func (c *Client) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline associated with the connection.
func (c *Client) SetWriteDeadline(t time.Time) error {
	return c.c.SetWriteDeadline(t)
}

//*******************************
// ADDITIONS START

func (c *Client) CheckExtFeature(ifi *Interface, feature uint) (bool, error) {
	return c.c.CheckExtFeature(ifi, feature)
}

func (c *Client) StartMulticastProcessing(ctx context.Context) <-chan []genetlink.Message {
	return c.c.StartMulticastProcessing(ctx)
}

func (c *Client) Authenticate(ifi *Interface, apMacAddr net.HardwareAddr, ssid string, freq uint32) error {
	return c.c.Authenticate(ifi, apMacAddr, ssid, freq)
}

func (c *Client) Associate(ifi *Interface, apMacAddr net.HardwareAddr, ssid string, freq uint32) error {
	return c.c.Associate(ifi, apMacAddr, ssid, freq)
}

func (c *Client) GetWiPhy(ifi *Interface) error {
	return c.c.GetWiPhy(ifi)
}

func (c *Client) SetWiPhy(ifi *Interface, freq uint32) error {
	return c.c.SetWiPhy(ifi, freq)
}

func (c *Client) SetTXQParams(ifi *Interface, queue uint8, aifs uint8, cw_min, cw_max, burst_time uint16) error {
	return c.c.SetTXQParams(ifi, queue, aifs, cw_min, cw_max, burst_time)
}

func (c *Client) AllBSS(ifi *Interface) ([]*BSS, error) {
	return c.c.AllBSS(ifi)
}

func (c *Client) SetBSS(ifi *Interface) error {
	return c.c.SetBSS(ifi)
}

func (c *Client) AddStation(ifi *Interface, mac net.HardwareAddr, aid uint16) error {
	return c.c.AddStation(ifi, mac, aid)
}

func (c *Client) SetStation(ifi *Interface, mac net.HardwareAddr, aid, staCap, listenInterval uint16, suppRates []byte, mask, set uint64) error {
	return c.c.SetStation(ifi, mac, aid, staCap, listenInterval, suppRates, mask, set)
}

func (c *Client) SetStationFlags(ifi *Interface, mac net.HardwareAddr, mask, set uint64) error {
	return c.c.SetStationFlags(ifi, mac, mask, set)
}

func (c *Client) DelStation(ifi *Interface, mac net.HardwareAddr) error {
	return c.c.DelStation(ifi, mac)
}

func (c *Client) SendProbeResponseFrame(ifi *Interface, dstMACAddr net.HardwareAddr, ssid string, freq uint32, freqChannel byte) error {
	return c.c.SendProbeResponseFrame(ifi, dstMACAddr, ssid, freq, freqChannel)
}

func (c *Client) SendAuthResponseFrame(ifi *Interface, dstMACAddr net.HardwareAddr, freq uint32, algo, status uint16) error {
	return c.c.SendAuthResponseFrame(ifi, dstMACAddr, freq, algo, status)
}

func (c *Client) SendAssocResponseFrame(ifi *Interface, dstMACAddr net.HardwareAddr, freq uint32, aid, capInfo, status uint16) error {
	return c.c.SendAssocResponseFrame(ifi, dstMACAddr, freq, aid, capInfo, status)
}

func (c *Client) SendFrame(ifi *Interface, freq uint32, data []byte) error {
	return c.c.SendFrame(ifi, freq, data)
}

func (c *Client) RegisterUnexpectedFrames(ifi *Interface) error {
	return c.c.RegisterUnexpectedFrames(ifi)
}

func (c *Client) TriggerScan(ifi *Interface) error {
	return c.c.TriggerScan(ifi)
}

func (c *Client) JoinMulticastGroup(grp string) error {
	return c.c.JoinMulticastGroup(grp)
}
func (c *Client) LeaveMulticastGroup(grp string) error {
	return c.c.LeaveMulticastGroup(grp)
}

func (c *Client) StartAP(ifi *Interface, ssid string, freqChannel byte) error {
	return c.c.StartAP(ifi, ssid, freqChannel)
}

func (c *Client) StopAP(ifi *Interface) error {
	return c.c.StopAP(ifi)
}

func (c *Client) RegisterFrame(ifi *Interface, frameType uint16, frameMatch []byte) error {
	return c.c.RegisterFrame(ifi, frameType, frameMatch)
}

func (c *Client) SetBeacon(ifi *Interface, ssid string, freqChannel byte) error {
	return c.c.SetBeacon(ifi, ssid, freqChannel)
}

func (c *Client) RegisterBeacons(ifi *Interface) error {
	return c.c.RegisterBeacons(ifi)
}

func (c *Client) SetMulticastToUnicast(ifi *Interface) error {
	return c.c.SetMulticastToUnicast(ifi)
}

func (c *Client) DeleteStation(ifi *Interface) error {
	return c.c.DeleteStation(ifi)
}

func (c *Client) DeleteKey(ifi *Interface, keyIdx uint8) error {
	return c.c.DeleteKey(ifi, keyIdx)
}

func (c *Client) GetInterface(ifi *Interface) ([]*Interface, error) {
	return c.c.GetInterface(ifi)
}

func (c *Client) SetInterfaceToAPMode(ifi *Interface) error {
	// return c.c.SetInterfaceToAPMode(ifi)
	return c.c.SetInterfaceMode(ifi, unix.NL80211_IFTYPE_AP)
}
func (c *Client) SetInterfaceToStationMode(ifi *Interface) error {
	return c.c.SetInterfaceMode(ifi, unix.NL80211_IFTYPE_STATION)
}

// ADDITIONS END
//********************************
