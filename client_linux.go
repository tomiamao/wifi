//go:build linux
// +build linux

package wifi

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"
	"unicode/utf8"

	"log"

	"github.com/josharian/native"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/sys/unix"
)

// A client is the Linux implementation of osClient, which makes use of
// netlink, generic netlink, and nl80211 to provide access to WiFi device
// actions and statistics.
type client struct {
	c             *genetlink.Conn
	familyID      uint16
	familyVersion uint8
	groups        []genetlink.MulticastGroup
}

// newClient dials a generic netlink connection and verifies that nl80211
// is available for use by this package.
func newClient() (*client, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, err
	}

	// Make a best effort to apply the strict options set to provide better
	// errors and validation. We don't apply Strict in the constructor because
	// this library is widely used on a range of kernels and we can't guarantee
	// it will always work on older kernels.
	for _, o := range []netlink.ConnOption{
		netlink.ExtendedAcknowledge,
		netlink.GetStrictCheck,
		netlink.NoENOBUFS,
	} {
		_ = c.SetOption(o, true)
	}

	return initClient(c)
}

func initClient(c *genetlink.Conn) (*client, error) {
	family, err := c.GetFamily(unix.NL80211_GENL_NAME)
	if err != nil {
		// Ensure the genl socket is closed on error to avoid leaking file
		// descriptors.
		_ = c.Close()
		return nil, err
	}

	return &client{
		c:             c,
		familyID:      family.ID,
		familyVersion: family.Version,
		groups:        family.Groups,
	}, nil
}

// Close closes the client's generic netlink connection.
func (c *client) Close() error { return c.c.Close() }

// SetDeadline sets the read and write deadlines associated with the connection.
func (c *client) SetDeadline(t time.Time) error {
	return c.c.SetDeadline(t)
}

// SetReadDeadline sets the read deadline associated with the connection.
func (c *client) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline associated with the connection.
func (c *client) SetWriteDeadline(t time.Time) error {
	return c.c.SetWriteDeadline(t)
}

// get performs a request/response interaction with nl80211.
func (c *client) get(
	cmd uint8,
	flags netlink.HeaderFlags,
	ifi *Interface,
	// May be nil; used to apply optional parameters.
	params func(ae *netlink.AttributeEncoder),
) ([]genetlink.Message, error) {
	ae := netlink.NewAttributeEncoder()
	ifi.encode(ae)
	if params != nil {
		// Optionally apply more parameters to the attribute encoder.
		params(ae)
	}

	// Note: don't send netlink.Acknowledge
	// or we get an extra message back from
	// the kernel which doesn't seem useful as of now.
	return c.execute(cmd, flags, ae)
}

// execute executes the specified command with additional header flags and input
// netlink request attributes. The netlink.Request header flag is automatically
// set.
func (c *client) execute(
	cmd uint8,
	flags netlink.HeaderFlags,
	ae *netlink.AttributeEncoder,
) ([]genetlink.Message, error) {
	b, err := ae.Encode()
	if err != nil {
		return nil, err
	}

	return c.c.Execute(
		genetlink.Message{
			Header: genetlink.Header{
				Command: cmd,
				Version: c.familyVersion,
			},
			Data: b,
		},
		// Always pass the genetlink family ID and request flag.
		c.familyID,
		netlink.Request|flags,
	)
}

// Interfaces requests that nl80211 return a list of all WiFi interfaces present
// on this system.
func (c *client) Interfaces() ([]*Interface, error) {
	// Ask nl80211 to dump a list of all WiFi interfaces
	msgs, err := c.get(
		unix.NL80211_CMD_GET_INTERFACE,
		netlink.Dump,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}

	return parseInterfaces(msgs)
}

// Connect starts connecting the interface to the specified ssid.
func (c *client) Connect(ifi *Interface, ssid string) error {
	// Ask nl80211 to connect to the specified SSID.
	_, err := c.get(
		unix.NL80211_CMD_CONNECT,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Bytes(unix.NL80211_ATTR_SSID, []byte(ssid))
			ae.Uint32(unix.NL80211_ATTR_AUTH_TYPE, unix.NL80211_AUTHTYPE_OPEN_SYSTEM)
		},
	)
	return err
}

// Disconnect disconnects the interface.
func (c *client) Disconnect(ifi *Interface) error {
	// Ask nl80211 to disconnect.
	_, err := c.get(
		unix.NL80211_CMD_DISCONNECT,
		netlink.Acknowledge,
		ifi,
		nil,
	)
	return err
}

// ConnectWPAPSK starts connecting the interface to the specified SSID using
// WPA.
func (c *client) ConnectWPAPSK(ifi *Interface, ssid, psk string) error {
	support, err := c.CheckExtFeature(ifi, unix.NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK)
	if err != nil {
		log.Printf("checkExtFeature NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK not supported\n")
		return err
	}
	if !support {
		log.Printf("NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK not supported\n")
		// return errNotSupported
		return fmt.Errorf("errNotSupported")
	}

	support, err = c.CheckExtFeature(ifi, unix.NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X)
	if err != nil {
		log.Printf("checkExtFeature NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X not supported\n")
		return err
	}
	if !support {
		log.Printf("NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X not supported\n")
		return fmt.Errorf("errNotSupported")
	}

	// Ask nl80211 to connect to the specified SSID with key..
	_, err = c.get(
		unix.NL80211_CMD_CONNECT,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			// TODO(mdlayher): document these or build from bitflags.
			const (
				cipherSuites = 0xfac04
				akmSuites    = 0xfac02
			)

			ae.Bytes(unix.NL80211_ATTR_SSID, []byte(ssid))
			ae.Uint32(unix.NL80211_ATTR_WPA_VERSIONS, unix.NL80211_WPA_VERSION_2)
			ae.Uint32(unix.NL80211_ATTR_CIPHER_SUITE_GROUP, cipherSuites)
			ae.Uint32(unix.NL80211_ATTR_CIPHER_SUITES_PAIRWISE, cipherSuites)
			ae.Uint32(unix.NL80211_ATTR_AKM_SUITES, akmSuites)
			ae.Flag(unix.NL80211_ATTR_WANT_1X_4WAY_HS, true)
			ae.Bytes(
				unix.NL80211_ATTR_PMK,
				wpaPassphrase([]byte(ssid), []byte(psk)),
			)
			ae.Uint32(unix.NL80211_ATTR_AUTH_TYPE, unix.NL80211_AUTHTYPE_OPEN_SYSTEM)
		},
	)

	log.Printf("client::ConnectWPAPSK() error - %s\n", err)
	return err
}

// wpaPassphrase computes a WPA passphrase given an SSID and preshared key.
func wpaPassphrase(ssid, psk []byte) []byte {
	return pbkdf2.Key(psk, ssid, 4096, 32, sha1.New)
}

// BSS requests that nl80211 return the BSS for the specified Interface.
func (c *client) BSS(ifi *Interface) (*BSS, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_SCAN,
		netlink.Dump,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			if ifi.HardwareAddr != nil {
				ae.Bytes(unix.NL80211_ATTR_MAC, ifi.HardwareAddr)
			}
		},
	)
	if err != nil {
		return nil, err
	}

	return parseBSS(msgs)
}

// StationInfo requests that nl80211 return all station info for the specified
// Interface.
func (c *client) StationInfo(ifi *Interface) ([]*StationInfo, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_STATION,
		netlink.Dump,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			if ifi.HardwareAddr != nil {
				ae.Bytes(unix.NL80211_ATTR_MAC, ifi.HardwareAddr)
			}
		},
	)
	if err != nil {
		return nil, err
	}

	stations := make([]*StationInfo, len(msgs))
	for i := range msgs {
		if stations[i], err = parseStationInfo(msgs[i].Data); err != nil {
			return nil, err
		}
	}

	return stations, nil
}

// *******************************
// ADDITIONS START

func (c *client) SetRegulatoryDomain(alpha2 string) error {
	_, err := c.get(
		unix.NL80211_CMD_REQ_SET_REG,
		netlink.Acknowledge,
		nil,
		func(ae *netlink.AttributeEncoder) {
			ae.Bytes(unix.NL80211_ATTR_REG_ALPHA2, []byte(alpha2))
		},
	)

	return err
}

func (c *client) GetRegulatoryDomain(ifi *Interface) error {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_REG,
		0,
		nil,
		func(ae *netlink.AttributeEncoder) {
		},
	)

	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return err
		}

		if err := ifi.parseAttributes(attrs); err != nil {
			return err
		}
	}

	return err
}

func (c *client) EnablePowerSaver(ifi *Interface) error {
	_, err := c.get(
		unix.NL80211_CMD_SET_POWER_SAVE,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Uint8(unix.NL80211_ATTR_PS_STATE, 0x1)
		},
	)

	return err
}
func (c *client) DisablePowerSaver(ifi *Interface) error {
	_, err := c.get(
		unix.NL80211_CMD_SET_POWER_SAVE,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Uint8(unix.NL80211_ATTR_PS_STATE, 0x0)
		},
	)

	return err
}

func (c *client) GetPowerSaverStatus(ifi *Interface) error {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_POWER_SAVE,
		0,
		ifi,
		func(ae *netlink.AttributeEncoder) {
		},
	)

	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return err
		}

		if err := ifi.parseAttributes(attrs); err != nil {
			return err
		}
	}

	return err
}

func (c *client) Authenticate(ifi *Interface, apMacAddr net.HardwareAddr, ssid string, freq uint32) error {
	_, err := c.get(
		unix.NL80211_CMD_AUTHENTICATE,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(ifi.Index))
			ae.Uint32(unix.NL80211_ATTR_WIPHY_FREQ, freq)
			ae.Bytes(unix.NL80211_ATTR_MAC, apMacAddr)
			ae.Bytes(unix.NL80211_ATTR_SSID, []byte(ssid))
			ae.Uint32(unix.NL80211_ATTR_AUTH_TYPE, unix.NL80211_AUTHTYPE_OPEN_SYSTEM)
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (c *client) Associate(ifi *Interface, apMacAddr net.HardwareAddr, ssid string, freq uint32) error {
	const (
		cipherSuites = 0xfac04
		akmSuites    = 0xfac02
	)

	_, err := c.get(
		unix.NL80211_CMD_ASSOCIATE,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			// ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(ifi.Index))
			ae.Uint32(unix.NL80211_ATTR_WIPHY_FREQ, freq)
			ae.Bytes(unix.NL80211_ATTR_MAC, apMacAddr)
			ae.Bytes(unix.NL80211_ATTR_SSID, []byte(ssid))

			ae.Uint32(unix.NL80211_ATTR_WPA_VERSIONS, unix.NL80211_WPA_VERSION_2)
			ae.Uint32(unix.NL80211_ATTR_CIPHER_SUITES_PAIRWISE, cipherSuites)
			ae.Uint32(unix.NL80211_ATTR_CIPHER_SUITE_GROUP, cipherSuites)
			ae.Uint32(unix.NL80211_ATTR_CIPHER_SUITE_GROUP, cipherSuites)
			ae.Uint32(unix.NL80211_ATTR_AKM_SUITES, akmSuites)
		},
	)

	return err
}

// leave multicast group
func (c *client) LeaveMulticastGroup(grp string) error {
	for _, group := range c.groups {
		if group.Name == grp {
			err := c.c.LeaveGroup(group.ID)
			if err != nil {
				log.Printf("leave group  failed - %s\n", err)
				return err
			}
			return nil
		}
	}
	return nil
}

// join multicast group
func (c *client) JoinMulticastGroup(grp string) error {
	for _, group := range c.groups {
		if group.Name == grp {
			err := c.c.JoinGroup(group.ID)
			if err != nil {
				log.Printf("join group  failed - %s\n", err)
				return err
			}
			return nil
		}
	}
	return nil
}

func (c *client) StartMulticastProcessing(ctx context.Context) <-chan []genetlink.Message {
	return c.processMulticastEvents(ctx)
}

func (c *client) processMulticastEvents(ctx context.Context) <-chan []genetlink.Message {
	resp := make(chan []genetlink.Message)

	go func() {
		for {
			c.c.SetReadDeadline(time.Now().Add(10 * time.Second))
			select {
			case <-ctx.Done():
				close(resp)
				return
			default:
				genl_msgs, _, err := c.c.Receive()
				if err != nil {
					// check if it is a read timeout
					if err.(*netlink.OpError).Timeout() {
						log.Printf("netlink multicast event read timeout - %s\n", err)
						continue
					} else {
						log.Printf("netlink multicast event receive failed - %s\n", err)
						// close(resp)
						// return
						continue
					}
				}

				// stream messages to caller
				resp <- genl_msgs
			}
		}
	}()

	return resp
}

func (c *client) SendProbeResponseFrame(ifi *Interface, dstMACAddr net.HardwareAddr, ssid string, freq uint32, freqChannel byte) error {
	beaconHead := BeaconHead{
		ByteOrder: native.Endian,
		FC:        0x0050, // protocol=0x0, Type=0x0 (mgmt) SubType=0x50 (Probe Response), Flags=0x00
		Duration:  0x0,
		DA:        dstMACAddr,
		SA:        ifi.HardwareAddr,
		BSSID:     ifi.HardwareAddr,
		SeqCtlr:   0x0,
		// Frame Body
		Timestamp:      []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		BeaconInterval: 0x0064,
		CapabilityInfo: 0x401, // bits set: ESS, Short Slot time
	}
	(&beaconHead).SetSSIDIE(ssid)
	(&beaconHead).AppendSupportedRateIE(true, 1)   // madatory 1Mbps
	(&beaconHead).AppendSupportedRateIE(true, 2)   // madatory 2Mbps
	(&beaconHead).AppendSupportedRateIE(true, 5.5) // madatory 5.5Mbps
	(&beaconHead).AppendSupportedRateIE(true, 11)  // madatory 11Mbps
	(&beaconHead).AppendSupportedRateIE(false, 6)  // optional 6Mbps
	(&beaconHead).AppendSupportedRateIE(false, 9)  // optional 9Mbps
	(&beaconHead).AppendSupportedRateIE(false, 12) // optional 12Mbps
	(&beaconHead).AppendSupportedRateIE(false, 18) // optional 18Mbps
	(&beaconHead).SetDSParamIE(freqChannel)

	beaconTail := BeaconTail{}
	(&beaconTail).SetERPIE()
	(&beaconTail).AppendExtendedSupportedRateIE(false, 24) // optional 24Mbps
	(&beaconTail).AppendExtendedSupportedRateIE(false, 36) // optional 36Mbps
	(&beaconTail).AppendExtendedSupportedRateIE(false, 48) // optional 48Mbps
	(&beaconTail).AppendExtendedSupportedRateIE(false, 54) // optional 54Mbps
	(&beaconTail).SetMDIE()
	(&beaconTail).SetExtendedCapabilties()

	data := make([]byte, 0)

	data = append(data, beaconHead.Serialize()...)
	data = append(data, beaconTail.Serialize()...)

	return c.SendFrame(ifi, freq, data)
}

func (c *client) SendProbeResponseFrame5GHz(ifi *Interface, dstMACAddr net.HardwareAddr, ssid string, freq uint32, freqChannel byte, rsnEnable bool) error {
	beaconHead := BeaconHead{
		ByteOrder: native.Endian,
		FC:        0x0050, // protocol=0x0, Type=0x0 (mgmt) SubType=0x50 (Probe Response), Flags=0x00
		Duration:  0x0,
		DA:        dstMACAddr,
		SA:        ifi.HardwareAddr,
		BSSID:     ifi.HardwareAddr,
		SeqCtlr:   0x0,
		// Frame Body
		Timestamp:      []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		BeaconInterval: 0x0064,
		CapabilityInfo: 0x01, // bits set: ESS
	}
	(&beaconHead).SetSSIDIE(ssid)
	(&beaconHead).AppendSupportedRateIE(true, 6)   // optional 6Mbps
	(&beaconHead).AppendSupportedRateIE(false, 9)  // optional 9Mbps
	(&beaconHead).AppendSupportedRateIE(true, 12)  // optional 12Mbps
	(&beaconHead).AppendSupportedRateIE(false, 18) // optional 18Mbps
	(&beaconHead).AppendSupportedRateIE(true, 24)  // optional 24Mbps
	(&beaconHead).AppendSupportedRateIE(false, 36) // optional 36Mbps
	(&beaconHead).AppendSupportedRateIE(false, 48) // optional 48Mbps
	(&beaconHead).AppendSupportedRateIE(false, 54) // optional 54Mbps
	(&beaconHead).SetDSParamIE(freqChannel)

	beaconTail := BeaconTail2{}
	(&beaconTail).SetExtendedSupportedRates()
	if rsnEnable {
		(&beaconTail).SetRSN()
	}
	(&beaconTail).SecondElementIE()
	(&beaconTail).SetHTCapabilties()
	(&beaconTail).SetHTOperation()
	(&beaconTail).SetExtendedCapabilties()
	(&beaconTail).SetTag191()
	(&beaconTail).SetTag192()
	(&beaconTail).EighthElementIE()
	(&beaconTail).NinthElementIE()

	data := make([]byte, 0)

	data = append(data, beaconHead.Serialize()...)
	data = append(data, beaconTail.Serialize()...)

	return c.SendFrame(ifi, freq, data)
}

func (c *client) SendAuthResponseFrame(ifi *Interface, dstMACAddr net.HardwareAddr, freq uint32, algo, status uint16) error {
	authResp := AuthResp{
		ByteOrder: native.Endian,
		FC:        0x00B0, // protocol=0x0, Type=0x0 (mgmt) SubType=0xB0 (Auth Response), Flags=0x00
		Duration:  0x0,
		DA:        dstMACAddr,
		SA:        ifi.HardwareAddr,
		BSSID:     ifi.HardwareAddr,
		SeqCtlr:   0x0,
		// Frame Body
		Algorithm: algo,
		Sequence:  2,
		Status:    status,
	}

	return c.SendFrame(ifi, freq, authResp.Serialize())
}

func (c *client) SendAssocResponseFrame(ifi *Interface, dstMACAddr net.HardwareAddr, freq uint32, aid, capInfo, status uint16) error {
	assocResp := AssocResp{
		ByteOrder: native.Endian,
		FC:        0x0010, // protocol=0x0, Type=0x0 (mgmt) SubType=0x10 (Assoc Response), Flags=0x00
		Duration:  0x0,
		DA:        dstMACAddr,
		SA:        ifi.HardwareAddr,
		BSSID:     ifi.HardwareAddr,
		SeqCtlr:   0x0,
		// Frame Body
		CapabilityInfo: capInfo,
		Status:         status,
		AID:            (0xC000 | aid), // first 2 bits of AID are set to 1
	}

	(&assocResp).AppendSupportedRateIE(true, 1)   // madatory 1Mbps
	(&assocResp).AppendSupportedRateIE(true, 2)   // madatory 2Mbps
	(&assocResp).AppendSupportedRateIE(true, 5.5) // madatory 5.5Mbps
	(&assocResp).AppendSupportedRateIE(true, 11)  // madatory 11Mbps
	(&assocResp).AppendSupportedRateIE(false, 6)  // optional 6Mbps
	(&assocResp).AppendSupportedRateIE(false, 9)  // optional 9Mbps
	(&assocResp).AppendSupportedRateIE(false, 12) // optional 12Mbps
	(&assocResp).AppendSupportedRateIE(false, 18) // optional 18Mbps

	(&assocResp).AppendExtendedSupportedRateIE(false, 24) // optional 24Mbps
	(&assocResp).AppendExtendedSupportedRateIE(false, 36) // optional 36Mbps
	(&assocResp).AppendExtendedSupportedRateIE(false, 48) // optional 48Mbps
	(&assocResp).AppendExtendedSupportedRateIE(false, 54) // optional 54Mbps

	(&assocResp).SetExtendedCapabilties()

	(&assocResp).SetBSSMaxIdlePeriod()

	return c.SendFrame(ifi, freq, assocResp.Serialize())
}

func (c *client) SendAssocResponseFrame5GHz(ifi *Interface, dstMACAddr net.HardwareAddr, freq uint32, aid, capInfo, status uint16) error {
	assocResp := AssocResp2{
		ByteOrder: native.Endian,
		FC:        0x0010, // protocol=0x0, Type=0x0 (mgmt) SubType=0x10 (Assoc Response), Flags=0x00
		Duration:  0x0,
		DA:        dstMACAddr,
		SA:        ifi.HardwareAddr,
		BSSID:     ifi.HardwareAddr,
		SeqCtlr:   0x0,
		// Frame Body
		CapabilityInfo: capInfo,
		Status:         status,
		AID:            (0xC000 | aid), // first 2 bits of AID are set to 1
	}

	(&assocResp).AppendSupportedRateIE(true, 6)   // optional 6Mbps
	(&assocResp).AppendSupportedRateIE(false, 9)  // optional 9Mbps
	(&assocResp).AppendSupportedRateIE(true, 12)  // optional 12Mbps
	(&assocResp).AppendSupportedRateIE(false, 18) // optional 18Mbps
	(&assocResp).AppendSupportedRateIE(true, 24)  // optional 24Mbps
	(&assocResp).AppendSupportedRateIE(false, 36) // optional 36Mbps
	(&assocResp).AppendSupportedRateIE(false, 48) // optional 48Mbps
	(&assocResp).AppendSupportedRateIE(false, 54) // optional 54Mbps

	(&assocResp).SetExtendedSupportedRates() // BSS membership HT_PHY 63.0(B) Mbit/s
	(&assocResp).SetHTCapabilties()
	(&assocResp).SetHTOperation()
	(&assocResp).SetTag191()
	(&assocResp).SetTag192()
	(&assocResp).SetExtendedCapabilties()
	(&assocResp).SetTag90()
	(&assocResp).NinthElementIE()

	return c.SendFrame(ifi, freq, assocResp.Serialize())
}

func (c *client) SendFrame(ifi *Interface, freq uint32, data []byte) error {
	_, err := c.get(
		unix.NL80211_CMD_FRAME,
		0, // NL80211_CMD_FRAME returns a response -> NL80211_CMD_FRAME_TX_STATUS, we need the NL80211_ATTR_COOKIE if we
		ifi,
		func(ae *netlink.AttributeEncoder) {
			/*
				if ifi.HardwareAddr != nil {
					ae.Bytes(unix.NL80211_ATTR_MAC, ifi.HardwareAddr)
				}
			*/
			// ae.Flag(unix.NL80211_ATTR_DONT_WAIT_FOR_ACK, true)
			ae.Uint32(unix.NL80211_ATTR_WIPHY_FREQ, freq)
			ae.Bytes(unix.NL80211_ATTR_FRAME, data)
		},
	)

	return err
}

func (c *client) AddStation(ifi *Interface, mac net.HardwareAddr, aid uint16) error {
	_, err := c.get(
		unix.NL80211_CMD_NEW_STATION,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Bytes(unix.NL80211_ATTR_MAC, mac)
			ae.Bytes(unix.NL80211_ATTR_STA_SUPPORTED_RATES, []byte{0x02, 0x04, 0x0B, 0x16}) // TODO:tomiamao hardcoded
			ae.Uint16(unix.NL80211_ATTR_STA_CAPABILITY, 0)
			ae.Uint16(unix.NL80211_ATTR_STA_AID, aid)
			ae.Uint16(unix.NL80211_ATTR_STA_LISTEN_INTERVAL, 0)

			/*
				* @NL80211_STA_FLAG_AUTHORIZED: station is authorized (802.1X)
				 * @NL80211_STA_FLAG_SHORT_PREAMBLE: station is capable of receiving frames
				 *	with short barker preamble
				 * @NL80211_STA_FLAG_WME: station is WME/QoS capable
				 * @NL80211_STA_FLAG_MFP: station uses management frame protection
				 * @NL80211_STA_FLAG_AUTHENTICATED: station is authenticated
				 * @NL80211_STA_FLAG_TDLS_PEER: station is a TDLS peer -- this flag should
				 *	only be used in managed mode (even in the flags mask). Note that the
				 *	flag can't be changed, it is only valid while adding a station, and
				 *	attempts to change it will silently be ignored (rather than rejected
				 *	as errors.)
				 * @NL80211_STA_FLAG_ASSOCIATED: station is associated; used with drivers
				 *	that support %NL80211_FEATURE_FULL_AP_CLIENT_STATE to transition a
				 *	previously added station into associated state

				 // Bit mapping
								NL80211_STA_FLAG_AUTHORIZED,      ---------> 1
								NL80211_STA_FLAG_SHORT_PREAMBLE, ---------> 2
								NL80211_STA_FLAG_WME,            ---------> 3
								NL80211_STA_FLAG_MFP,            ---------> 4
								NL80211_STA_FLAG_AUTHENTICATED,  ---------> 5
								NL80211_STA_FLAG_TDLS_PEER,      ---------> 6
								NL80211_STA_FLAG_ASSOCIATED,     ---------> 7

			*/

			/**
			 * struct nl80211_sta_flag_update - station flags mask/set
			 * @mask: mask of station flags to set
			 * @set: which values to set them to
			 *
			 * Both mask and set contain bits as per &enum nl80211_sta_flags.

			struct nl80211_sta_flag_update {
				__u32 mask;
				__u32 set;
			} __attribute__((packed));
			*/

			var mask uint64 = (1 << unix.NL80211_STA_FLAG_AUTHENTICATED) | (1 << unix.NL80211_STA_FLAG_ASSOCIATED)
			var set uint64 = 0

			ae.Uint64(unix.NL80211_ATTR_STA_FLAGS2, ((set << 32) | mask))
		},
	)

	return err
}

// update an existing station
func (c *client) SetStation(ifi *Interface, mac net.HardwareAddr, aid, staCap, listenInterval uint16, suppRates []byte, mask, set uint64) error {
	_, err := c.get(
		unix.NL80211_CMD_SET_STATION,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Bytes(unix.NL80211_ATTR_MAC, mac)

			ae.Bytes(unix.NL80211_ATTR_STA_SUPPORTED_RATES, suppRates)
			ae.Uint16(unix.NL80211_ATTR_STA_CAPABILITY, staCap)
			ae.Uint16(unix.NL80211_ATTR_STA_AID, aid)
			ae.Uint16(unix.NL80211_ATTR_STA_LISTEN_INTERVAL, listenInterval)

			ae.Uint64(unix.NL80211_ATTR_STA_FLAGS2, ((set << 32) | mask))
		},
	)

	return err
}

func (c *client) SetStation5GHz(ifi *Interface, mac net.HardwareAddr, aid, staCap, listenInterval uint16, suppRates, htCap, vhtCap []byte, mask, set uint64) error {
	_, err := c.get(
		unix.NL80211_CMD_SET_STATION,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Bytes(unix.NL80211_ATTR_MAC, mac)

			ae.Bytes(unix.NL80211_ATTR_STA_SUPPORTED_RATES, suppRates)
			ae.Uint16(unix.NL80211_ATTR_STA_CAPABILITY, staCap)
			ae.Uint16(unix.NL80211_ATTR_STA_AID, aid)
			ae.Uint16(unix.NL80211_ATTR_STA_LISTEN_INTERVAL, listenInterval)

			ae.Bytes(unix.NL80211_ATTR_HT_CAPABILITY, htCap)
			ae.Bytes(unix.NL80211_ATTR_VHT_CAPABILITY, vhtCap)

			ae.Uint64(unix.NL80211_ATTR_STA_FLAGS2, ((set << 32) | mask))
		},
	)

	return err
}

func (c *client) SetStationFlags(ifi *Interface, mac net.HardwareAddr, mask, set uint64) error {
	_, err := c.get(
		unix.NL80211_CMD_SET_STATION,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Bytes(unix.NL80211_ATTR_MAC, mac)

			ae.Uint64(unix.NL80211_ATTR_STA_FLAGS2, ((set << 32) | mask))
		},
	)

	return err
}

func (c *client) DelStation(ifi *Interface, mac net.HardwareAddr) error {
	_, err := c.get(
		unix.NL80211_CMD_DEL_STATION,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Bytes(unix.NL80211_ATTR_MAC, mac)
		},
	)

	return err
}

// List of scan status

// FreqToChannel returns the channel of the specified
// frequency (in MHz) for the 2.4GHz and 5GHz ranges.
func FreqToChannel(freq int) int {
	if freq == 2484 {
		return 14
	}
	if freq < 2484 {
		return (freq - 2407) / 5
	}
	return freq/5 - 1000
}

func ChannelToFreq5GHz(channel int) int {
	return (channel + 1000) * 5
}

func ChannelToFreq2GHz(channel int) int {
	if channel == 14 {
		return 2484
	}
	return (channel * 5) + 2407
}

type BeaconHead struct {
	ByteOrder binary.ByteOrder
	// MAC Header
	FC       uint16 // Frame Control - length 2
	Duration uint16 // length 2
	DA       net.HardwareAddr
	SA       net.HardwareAddr
	BSSID    net.HardwareAddr
	SeqCtlr  uint16 // len 2 bytes -> Fragment number (4 bits) + Sequence number (12 bits)
	// Frame Body
	// Fixed Fields
	Timestamp      []byte // len 8
	BeaconInterval uint16 // len 2
	CapabilityInfo uint16 // len 2
	// Information Elements (variable length)
	SSID           []byte
	SupportedRates []byte // variable
	DSParamSet     []byte
}

// rate in Mbps
func (b *BeaconHead) AppendSupportedRateIE(mandatory bool, rateMbps float64) error {
	if b.SupportedRates == nil {
		b.SupportedRates = make([]byte, 0)
	}

	var mandatoryBit byte = 0
	if mandatory {
		mandatoryBit = 0x80
	}
	val := mandatoryBit | byte(rateMbps*2)

	if len(b.SupportedRates) == 2 {
		return fmt.Errorf("invalid supported rate filed")
	}
	if len(b.SupportedRates) == 0 { // no previous supported rates configured
		b.SupportedRates = append(b.SupportedRates, 0x1, 0x1, val) // element ID, length
		return nil
	}

	if len(b.SupportedRates) != int(b.SupportedRates[1]+2) {
		return fmt.Errorf("invalid supported rate filed - invalid lengths")
	}

	// increase the current length
	b.SupportedRates[1]++
	// append new supported rate
	b.SupportedRates = append(b.SupportedRates, val)

	return nil
}

func (b *BeaconHead) SetSSIDIE(ssid string) error {
	b.SSID = make([]byte, 0)

	b.SSID = append(b.SSID, 0x0, byte(len(ssid))) // element ID, length
	b.SSID = append(b.SSID, []byte(ssid)...)

	return nil
}

// used by the 2.4GHz channel. Possbile Channel values range from 1-14, with 7 being the default
func (b *BeaconHead) SetDSParamIE(channel byte) error {
	b.DSParamSet = make([]byte, 0)
	b.DSParamSet = append(b.DSParamSet, 0x3, 0x1, channel) // element ID, length, channel
	return nil
}

func (b BeaconHead) Serialize() []byte {
	data := make([]byte, 0)

	fc := make([]byte, 2)
	b.ByteOrder.PutUint16(fc, b.FC)
	data = append(data, fc...)

	duration := make([]byte, 2)
	b.ByteOrder.PutUint16(duration, b.Duration)
	data = append(data, duration...)

	data = append(data, b.DA...)
	data = append(data, b.SA...)
	data = append(data, b.BSSID...)

	seqCtrl := make([]byte, 2)
	b.ByteOrder.PutUint16(seqCtrl, b.SeqCtlr)
	data = append(data, seqCtrl...)

	data = append(data, b.Timestamp...)

	beaconInterval := make([]byte, 2)
	b.ByteOrder.PutUint16(beaconInterval, b.BeaconInterval)
	data = append(data, beaconInterval...)

	capabilityInfo := make([]byte, 2)
	b.ByteOrder.PutUint16(capabilityInfo, b.CapabilityInfo)
	data = append(data, capabilityInfo...)

	data = append(data, b.SSID...)

	data = append(data, b.SupportedRates...)
	data = append(data, b.DSParamSet...)

	return data
}

type BeaconTail struct {
	ERP                    []byte
	ExtendedSupportedRates []byte
	MDIE                   []byte //  MDIE (Mobility Domain Information Element)
	ExtendedCapabilties    []byte
}

func (b *BeaconTail) SetERPIE() error {
	b.ERP = make([]byte, 0)
	b.ERP = append(b.ERP, 0x2A, 0x1, 0x4) // element ID, length, set Barker Preamble mode
	return nil
}

func (b *BeaconTail) SetExtendedCapabilties() error {
	b.ExtendedCapabilties = make([]byte, 0)
	b.ExtendedCapabilties = append(b.ExtendedCapabilties, 0x7F, 0x8, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40) // element ID, length, Extended capabilites
	return nil
}

// MDIE (Mobility Domain Information Element)
func (b *BeaconTail) SetMDIE() error {
	b.MDIE = make([]byte, 0)
	b.MDIE = append(b.MDIE, 0x3B, 0x02, 0x51, 0x00) // element ID, length, MDIE
	return nil
}

// rate in Mbps
func (b *BeaconTail) AppendExtendedSupportedRateIE(mandatory bool, rateMbps uint) error {
	if b.ExtendedSupportedRates == nil {
		b.ExtendedSupportedRates = make([]byte, 0)
	}

	var mandatoryBit byte = 0
	if mandatory {
		mandatoryBit = 0x80
	}
	val := mandatoryBit | byte(rateMbps*2)

	if len(b.ExtendedSupportedRates) == 2 {
		return fmt.Errorf("invalid supported rate filed")
	}
	if len(b.ExtendedSupportedRates) == 0 { // no previous supported rates configured
		b.ExtendedSupportedRates = append(b.ExtendedSupportedRates, 0x32, 0x1, val) // element ID, length
		return nil
	}

	if len(b.ExtendedSupportedRates) != int(b.ExtendedSupportedRates[1]+2) {
		return fmt.Errorf("invalid supported rate filed - invalid lengths")
	}

	// increase the current length
	b.ExtendedSupportedRates[1]++
	// append new supported rate
	b.ExtendedSupportedRates = append(b.ExtendedSupportedRates, val)

	return nil
}

func (b BeaconTail) Serialize() []byte {
	data := make([]byte, 0)
	data = append(data, b.ERP...)
	data = append(data, b.ExtendedSupportedRates...)
	data = append(data, b.MDIE...)
	data = append(data, b.ExtendedCapabilties...)

	return data
}

func (c *client) DeleteStation(ifi *Interface) error {
	_, err := c.get(
		unix.NL80211_CMD_DEL_STATION,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
		},
	)

	return err
}

func (c *client) DeleteKey(ifi *Interface, keyIdx uint8) error {
	_, err := c.get(
		unix.NL80211_CMD_DEL_KEY,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Uint8(unix.NL80211_ATTR_KEY_IDX, keyIdx)
		},
	)

	return err
}

func (c *client) StopAP(ifi *Interface) error {
	_, err := c.get(
		unix.NL80211_CMD_STOP_AP,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			// ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(ifi.Index))
		},
	)

	return err
}

/*

Ours
79.656817

< Request: Start AP (0x0f) len 152 [ack]                                                                                                                                                                    79.656817
    Interface Index: 8 (0x00000008)
    Beacon Head: len 57
        80 00 00 00 ff ff ff ff ff ff 04 f0 21 b5 9b 48  ............!..H
        04 f0 21 b5 9b 48 00 00 00 00 00 00 00 00 00 00  ..!..H..........
        64 00 01 04 01 07 12 14 16 0c 12 18 24 00 07 42  d...........$..B
        6f 78 57 69 46 69 03 01 06                       oxWiFi...
    Beacon Tail: len 9
        2a 01 04 01 04 30 48 60 6c                       *....0H`l
    SSID: len 7
        42 6f 78 57 69 46 69                             BoxWiFi
    Hidden SSID: 0 (0x00000000)
    Beacon Interval: 100 (0x00000064)
    DTIM Period: 2 (0x00000002)
    Auth Type: 0 (0x00000000)
    Information Elements: len 0
    IE Probe Response: len 0
    IE Assoc Response: len 0
    Socket Owns Interface/Connection: true
    Control Port over NL80211: true

/*
*	Information Elements
*	https://www.nsnam.org/docs/release/3.15/doxygen/wifi-information-element_8h_source.html
*/

/*

< Request: Start AP (0x0f) len 284 [ack]                                                                                                                                                                                                                              10.950167
    Interface Index: 6 (0x00000006)
    Beacon Head: len 58
        80 00 00 00 ff ff ff ff ff ff 04 f0 21 b5 9b 48  ............!..H
        04 f0 21 b5 9b 48 00 00 00 00 00 00 00 00 00 00  ..!..H..........
        64 00 01 00 00 07 42 6f 78 57 69 46 69 01 08 8c  d.....BoxWiFi...
        12 98 24 b0 48 60 6c 03 01 24                    ..$.H`l..$
    Beacon Tail: len 123
        32 02 ff fe 3b 02 80 00 2d 1a 6e 08 1b ff ff 00  2...;...-.n.....
        00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00  ................
        00 00 00 00 3d 16 24 05 00 00 00 00 00 00 00 00  ....=.$.........
        00 00 00 00 00 00 00 00 00 00 00 00 7f 08 04 00  ................
        00 02 00 00 00 40 bf 0c a2 00 00 00 fa ff 00 00  .....@..........
        fa ff 00 00 c0 05 01 2a 00 fc ff c3 04 02 2e 2e  .......*........
        2e dd 18 00 50 f2 02 01 01 01 00 03 a4 00 00 27  ....P..........'
        a4 00 00 42 43 5e 00 62 32 2f 00                 ...BC^.b2/.
    Beacon Interval: 100 (0x00000064)
    DTIM Period: 2 (0x00000002)
    SSID: len 7
        42 6f 78 57 69 46 69                             BoxWiFi
    Hidden SSID: 0 (0x00000000)
    Information Elements: len 10
        Extended Capabilities: len 8
            Capability: bit  2: Extended channel switching
            Capability: bit 25: SSID list
            Capability: bit 62: Opmode Notification
            04 00 00 02 00 00 00 40                          .......@
    IE Probe Response: len 10
        Extended Capabilities: len 8
            Capability: bit  2: Extended channel switching
            Capability: bit 25: SSID list
            Capability: bit 62: Opmode Notification
            04 00 00 02 00 00 00 40                          .......@
    IE Assoc Response: len 10
        Extended Capabilities: len 8
            Capability: bit  2: Extended channel switching
            Capability: bit 25: SSID list
            Capability: bit 62: Opmode Notification
            04 00 00 02 00 00 00 40                          .......@

*/

// use channel 6 in the 2.4GHz spectrum - specify 6 for freqChannel
// use channel 40 in the 5GHz spectrum - specify 40 for freqChannel
func (c *client) StartAP(ifi *Interface, ssid string, freqChannel byte) error {
	_, err := c.get(
		unix.NL80211_CMD_START_AP,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			// ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(ifi.Index))
			beaconHead := BeaconHead{
				ByteOrder: native.Endian,
				FC:        0x0080, // protocol=0x0, Type=0x0 (mgmt) SubType=0x80 (Beacon), Flags=0x00
				Duration:  0x0,
				DA:        net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
				SA:        ifi.HardwareAddr,
				BSSID:     ifi.HardwareAddr,
				SeqCtlr:   0x0,
				// Frame Body
				Timestamp:      []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
				BeaconInterval: 0x0064,
				CapabilityInfo: 0x401, // bits set: ESS, Short Slot time
			}
			(&beaconHead).SetSSIDIE(ssid)
			(&beaconHead).AppendSupportedRateIE(true, 1)   // madatory 1Mbps
			(&beaconHead).AppendSupportedRateIE(true, 2)   // madatory 2Mbps
			(&beaconHead).AppendSupportedRateIE(true, 5.5) // madatory 5.5Mbps
			(&beaconHead).AppendSupportedRateIE(true, 11)  // madatory 11Mbps
			(&beaconHead).AppendSupportedRateIE(false, 6)  // optional 6Mbps
			(&beaconHead).AppendSupportedRateIE(false, 9)  // optional 9Mbps
			(&beaconHead).AppendSupportedRateIE(false, 12) // optional 12Mbps
			(&beaconHead).AppendSupportedRateIE(false, 18) // optional 18Mbps
			(&beaconHead).SetDSParamIE(freqChannel)
			ae.Bytes(unix.NL80211_ATTR_BEACON_HEAD, beaconHead.Serialize())

			beaconTail := BeaconTail{}
			(&beaconTail).SetERPIE()
			(&beaconTail).AppendExtendedSupportedRateIE(false, 24) // optional 24Mbps
			(&beaconTail).AppendExtendedSupportedRateIE(false, 36) // optional 36Mbps
			(&beaconTail).AppendExtendedSupportedRateIE(false, 48) // optional 48Mbps
			(&beaconTail).AppendExtendedSupportedRateIE(false, 54) // optional 54Mbps
			(&beaconTail).SetMDIE()
			(&beaconTail).SetExtendedCapabilties()
			ae.Bytes(unix.NL80211_ATTR_BEACON_TAIL, beaconTail.Serialize())

			ae.Uint32(unix.NL80211_ATTR_BEACON_INTERVAL, uint32(100)) // 100 TU  ==> 102.4ms
			// About TIM & DTIM ----> https://community.arubanetworks.com/blogs/gstefanick1/2016/01/25/80211-tim-and-dtim-information-elements
			ae.Uint32(unix.NL80211_ATTR_DTIM_PERIOD, uint32(2)) // A DTIM period field of 2 indicates every 2nd beacon is a DTIM.

			ae.Bytes(unix.NL80211_ATTR_SSID, []byte(ssid))
			ae.Uint32(unix.NL80211_ATTR_HIDDEN_SSID, uint32(unix.NL80211_HIDDEN_SSID_NOT_IN_USE))

			// ae.Uint32(unix.NL80211_ATTR_AUTH_TYPE, unix.NL80211_AUTHTYPE_OPEN_SYSTEM)

			// ae.Flag(unix.NL80211_ATTR_PRIVACY, false)

			// TODO: figure out what these values mean
			ae.Bytes(unix.NL80211_ATTR_IE, []byte{0x7F, 0x8, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40})
			ae.Bytes(unix.NL80211_ATTR_IE_PROBE_RESP, []byte{0x7F, 0x8, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40})
			ae.Bytes(unix.NL80211_ATTR_IE_ASSOC_RESP, []byte{0x7F, 0x8, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40})

			support, err := c.CheckExtFeature(ifi, unix.NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211)
			if err != nil {
				log.Printf("checkExtFeature NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211 error - %s\n", err)
			}
			if !support {
				log.Printf("checkExtFeature NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211 NOT supported\n")
			} else {
				log.Printf("checkExtFeature NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211 supported\n")
				/*
				   l_genl_msg_append_attr(cmd, NL80211_ATTR_SOCKET_OWNER, 0, NULL);
				   		l_genl_msg_append_attr(cmd,
				   				NL80211_ATTR_CONTROL_PORT_OVER_NL80211,
				   				0, NULL);
				*/
				// ae.Flag(unix.NL80211_ATTR_SOCKET_OWNER, true)
				// ae.Flag(unix.NL80211_ATTR_CONTROL_PORT_OVER_NL80211, true)
			}
		},
	)

	return err
}

type BeaconTail2 struct {
	ExtendedSupportedRates []byte // ID: 0x32 len: 2
	RSN                    []byte // ID: 0x30 len: 20 Robust security network
	SecondElement          []byte // ID: 0x3b len: 2
	HTCapabilties          []byte // ID: 0x2d len: 26
	HTOperation            []byte // ID: 0x3d len: 22
	ExtendedCapabilties    []byte
	Tag191                 []byte // ID: 0xbf len: 12
	Tag192                 []byte // ID: 0xc0 len: 5
	EighthElement          []byte // ID: 0xc3 len: 4
	NinthElement           []byte // ID: 0xdd len: 24
}

func (b *BeaconTail2) SetExtendedSupportedRates() error {
	b.ExtendedSupportedRates = make([]byte, 0)
	b.ExtendedSupportedRates = append(b.ExtendedSupportedRates, 0x32, 0x02, 0xFF, 0xFE) // element ID, length, params
	return nil
}

func (b *BeaconTail2) SetRSN() error {
	b.RSN = make([]byte, 0)
	// element ID: 48 (0x32)
	// len: 20 (0x14)

	// version: 0x1  (2 bytes)
	// Group Cipher OUI: 00-0F-AC
	// Group Cipher Type: 0x04

	// Pairwise Cipher suite count: 0x1  (2 bytes)
	// Pairwise Cipher OUI: 00-0F-AC
	// Pairwise Cipher Type: 0x04

	// Auth Key Mgmt Suite count: 0x1 (2 bytes)
	// Authentication Method AKM Suites: 00-0F-AC
	// Authentication Method AKM Suites Type: 0x02

	// RSN Capabilities: 0x0c 0x00

	/*
		RSN-IE also used to indicate what authentication methods are supported.
		The Authentication Key Management (AKM) suite indicate whether the station support 802.1X or PSK authentication.
		Below are the 3 different AKM suite values depend on the Authentication method used.
		00-0F-AC-01 (802.1X)
		00-0F-AC-02 (PSK)
		00-0F-AC-03 (FT over 802.1X)
	*/
	b.RSN = append(b.RSN, 0x30, 0x14, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, 0x0C, 0x00) // element ID, length, params
	return nil
}

func (b *BeaconTail2) SecondElementIE() error {
	b.SecondElement = make([]byte, 0)
	b.SecondElement = append(b.SecondElement, 0x3B, 0x02, 0x80, 0x00) // element ID, length, params
	return nil
}

func (b *BeaconTail2) SetHTCapabilties() error {
	b.HTCapabilties = make([]byte, 0)
	b.HTCapabilties = append(b.HTCapabilties, 0x2D, 0x1A, 0x6e, 0x08, 0x1b, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // element ID, length, params
	return nil
}

func (b *BeaconTail2) SetHTOperation() error {
	b.HTOperation = make([]byte, 0)
	b.HTOperation = append(b.HTOperation, 0x3D, 0x16, 0x24, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // element ID, length, params
	return nil
}

func (b *BeaconTail2) SetExtendedCapabilties() error {
	b.ExtendedCapabilties = make([]byte, 0)
	b.ExtendedCapabilties = append(b.ExtendedCapabilties, 0x7F, 0x8, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40) // element ID, length, Extended capabilites
	return nil
}

func (b *BeaconTail2) SetTag191() error {
	b.Tag191 = make([]byte, 0)
	b.Tag191 = append(b.Tag191, 0xBF, 0x0C, 0xa2, 0x00, 0x00, 0x00, 0xfa, 0xff, 0x00, 0x00, 0xfa, 0xff, 0x00, 0x00) // element ID, length, params
	return nil
}

func (b *BeaconTail2) SetTag192() error {
	b.Tag192 = make([]byte, 0)
	b.Tag192 = append(b.Tag192, 0xC0, 0x05, 0x01, 0x2a, 0x00, 0xfc, 0xff) // element ID, length, params
	return nil
}

func (b *BeaconTail2) EighthElementIE() error {
	b.EighthElement = make([]byte, 0)
	b.EighthElement = append(b.EighthElement, 0xC3, 0x04, 0x02, 0x2E, 0x2E, 0x2E) // element ID, length, params
	return nil
}

func (b *BeaconTail2) NinthElementIE() error {
	b.NinthElement = make([]byte, 0)
	b.NinthElement = append(b.NinthElement, 0xDD, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x01, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00) // element ID, length, params
	return nil
}

func (b BeaconTail2) Serialize() []byte {
	data := make([]byte, 0)

	data = append(data, b.ExtendedSupportedRates...)
	if b.RSN != nil {
		data = append(data, b.RSN...)
	}
	data = append(data, b.SecondElement...)
	data = append(data, b.HTCapabilties...)
	data = append(data, b.HTOperation...)
	data = append(data, b.ExtendedCapabilties...)
	data = append(data, b.Tag191...)
	data = append(data, b.Tag192...)
	data = append(data, b.EighthElement...)
	data = append(data, b.NinthElement...)

	return data
}

func (c *client) StartAP5GHz(ifi *Interface, ssid string, freqChannel byte, rsnEnable bool) error {
	_, err := c.get(
		unix.NL80211_CMD_START_AP,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			// ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(ifi.Index))
			capInfo := 0x01 // bits set: ESS  -----> 5GHz VHT operation  // Short slot time is an 802.11g-only feature and does not apply to 802.11a radios.
			if rsnEnable {
				capInfo = 0x11
			}

			beaconHead := BeaconHead{
				ByteOrder: native.Endian,
				FC:        0x0080, // protocol=0x0, Type=0x0 (mgmt) SubType=0x80 (Beacon), Flags=0x00
				Duration:  0x0,
				DA:        net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
				SA:        ifi.HardwareAddr,
				BSSID:     ifi.HardwareAddr,
				SeqCtlr:   0x0,
				// Frame Body
				Timestamp:      []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
				BeaconInterval: 0x0064,
				// CapabilityInfo: 0x401, // bits set: ESS, Short Slot time
				CapabilityInfo: uint16(capInfo), // bits set: ESS  -----> 5GHz VHT operation  // Short slot time is an 802.11g-only feature and does not apply to 802.11a radios.
			}
			(&beaconHead).SetSSIDIE(ssid)
			(&beaconHead).AppendSupportedRateIE(true, 6)   // optional 6Mbps
			(&beaconHead).AppendSupportedRateIE(false, 9)  // optional 9Mbps
			(&beaconHead).AppendSupportedRateIE(true, 12)  // optional 12Mbps
			(&beaconHead).AppendSupportedRateIE(false, 18) // optional 18Mbps
			(&beaconHead).AppendSupportedRateIE(true, 24)  // optional 24Mbps
			(&beaconHead).AppendSupportedRateIE(false, 36) // optional 36Mbps
			(&beaconHead).AppendSupportedRateIE(false, 48) // optional 48Mbps
			(&beaconHead).AppendSupportedRateIE(false, 54) // optional 54Mbps
			(&beaconHead).SetDSParamIE(freqChannel)
			ae.Bytes(unix.NL80211_ATTR_BEACON_HEAD, beaconHead.Serialize())

			beaconTail := BeaconTail2{}
			(&beaconTail).SetExtendedSupportedRates()
			if rsnEnable {
				(&beaconTail).SetRSN()
			}
			(&beaconTail).SecondElementIE()
			(&beaconTail).SetHTCapabilties()
			(&beaconTail).SetHTOperation()
			(&beaconTail).SetExtendedCapabilties()
			(&beaconTail).SetTag191()
			(&beaconTail).SetTag192()
			(&beaconTail).EighthElementIE()
			(&beaconTail).NinthElementIE()
			ae.Bytes(unix.NL80211_ATTR_BEACON_TAIL, beaconTail.Serialize())

			ae.Uint32(unix.NL80211_ATTR_BEACON_INTERVAL, uint32(100)) // 100 TU  ==> 102.4ms
			// About TIM & DTIM ----> https://community.arubanetworks.com/blogs/gstefanick1/2016/01/25/80211-tim-and-dtim-information-elements
			ae.Uint32(unix.NL80211_ATTR_DTIM_PERIOD, uint32(2)) // A DTIM period field of 2 indicates every 2nd beacon is a DTIM.

			ae.Bytes(unix.NL80211_ATTR_SSID, []byte(ssid))
			ae.Uint32(unix.NL80211_ATTR_HIDDEN_SSID, uint32(unix.NL80211_HIDDEN_SSID_NOT_IN_USE))

			// TODO: figure out what these values mean
			ae.Bytes(unix.NL80211_ATTR_IE, []byte{0x7F, 0x8, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40})
			ae.Bytes(unix.NL80211_ATTR_IE_PROBE_RESP, []byte{0x7F, 0x8, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40})
			ae.Bytes(unix.NL80211_ATTR_IE_ASSOC_RESP, []byte{0x7F, 0x8, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40})

			support, err := c.CheckExtFeature(ifi, unix.NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211)
			if err != nil {
				log.Printf("checkExtFeature NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211 error - %s\n", err)
			}
			if !support {
				log.Printf("checkExtFeature NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211 NOT supported\n")
			} else {
				log.Printf("checkExtFeature NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211 supported\n")
				/*
				   l_genl_msg_append_attr(cmd, NL80211_ATTR_SOCKET_OWNER, 0, NULL);
				   		l_genl_msg_append_attr(cmd,
				   				NL80211_ATTR_CONTROL_PORT_OVER_NL80211,
				   				0, NULL);
				*/
				ae.Flag(unix.NL80211_ATTR_SOCKET_OWNER, true)
				ae.Flag(unix.NL80211_ATTR_CONTROL_PORT_OVER_NL80211, true)
			}

			if rsnEnable {
				const (
					cipherSuites = 0xfac04
					akmSuites    = 0xfac02
				)

				ae.Flag(unix.NL80211_ATTR_PRIVACY, true)
				ae.Uint32(unix.NL80211_ATTR_AUTH_TYPE, unix.NL80211_AUTHTYPE_OPEN_SYSTEM)
				ae.Uint32(unix.NL80211_ATTR_WPA_VERSIONS, unix.NL80211_WPA_VERSION_2)
				ae.Uint32(unix.NL80211_ATTR_CIPHER_SUITE_GROUP, cipherSuites)
				ae.Uint32(unix.NL80211_ATTR_CIPHER_SUITES_PAIRWISE, cipherSuites)
				ae.Uint32(unix.NL80211_ATTR_AKM_SUITES, akmSuites)
			}
		},
	)

	return err
}

func (c *client) SetBeacon(ifi *Interface, ssid string, freqChannel byte) error {
	_, err := c.get(
		unix.NL80211_CMD_SET_BEACON,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			// ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(ifi.Index))
			beaconHead := BeaconHead{
				ByteOrder: native.Endian,
				FC:        0x0080, // protocol=0x0, Type=0x0 (mgmt) SubType=0x80 (Beacon), Flags=0x00
				Duration:  0x0,
				DA:        net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
				SA:        ifi.HardwareAddr,
				BSSID:     ifi.HardwareAddr,
				SeqCtlr:   0x0,
				// Frame Body
				Timestamp:      []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
				BeaconInterval: 0x0064,
				CapabilityInfo: 0x401, // bits set: ESS, Short Slot time
			}
			(&beaconHead).SetSSIDIE(ssid)
			(&beaconHead).AppendSupportedRateIE(true, 1)   // madatory 1Mbps
			(&beaconHead).AppendSupportedRateIE(true, 2)   // madatory 2Mbps
			(&beaconHead).AppendSupportedRateIE(true, 5.5) // madatory 5.5Mbps
			(&beaconHead).AppendSupportedRateIE(true, 11)  // madatory 11Mbps
			(&beaconHead).AppendSupportedRateIE(false, 6)  // optional 6Mbps
			(&beaconHead).AppendSupportedRateIE(false, 9)  // optional 9Mbps
			(&beaconHead).AppendSupportedRateIE(false, 12) // optional 12Mbps
			(&beaconHead).AppendSupportedRateIE(false, 18) // optional 18Mbps
			(&beaconHead).SetDSParamIE(freqChannel)
			ae.Bytes(unix.NL80211_ATTR_BEACON_HEAD, beaconHead.Serialize())

			beaconTail := BeaconTail{}
			(&beaconTail).SetERPIE()
			(&beaconTail).AppendExtendedSupportedRateIE(false, 24) // optional 24Mbps
			(&beaconTail).AppendExtendedSupportedRateIE(false, 36) // optional 36Mbps
			(&beaconTail).AppendExtendedSupportedRateIE(false, 48) // optional 48Mbps
			(&beaconTail).AppendExtendedSupportedRateIE(false, 54) // optional 54Mbps
			(&beaconTail).SetMDIE()
			(&beaconTail).SetExtendedCapabilties()
			ae.Bytes(unix.NL80211_ATTR_BEACON_TAIL, beaconTail.Serialize())

			ae.Uint32(unix.NL80211_ATTR_BEACON_INTERVAL, uint32(100)) // 100 TU  ==> 102.4ms
			// About TIM & DTIM ----> https://community.arubanetworks.com/blogs/gstefanick1/2016/01/25/80211-tim-and-dtim-information-elements
			ae.Uint32(unix.NL80211_ATTR_DTIM_PERIOD, uint32(2)) // A DTIM period field of 2 indicates every 2nd beacon is a DTIM.

			ae.Bytes(unix.NL80211_ATTR_SSID, []byte(ssid))
			ae.Uint32(unix.NL80211_ATTR_HIDDEN_SSID, uint32(unix.NL80211_HIDDEN_SSID_NOT_IN_USE))

			// ae.Uint32(unix.NL80211_ATTR_AUTH_TYPE, unix.NL80211_AUTHTYPE_OPEN_SYSTEM)

			// ae.Flag(unix.NL80211_ATTR_PRIVACY, false)

			// TODO: figure out what these values mean
			ae.Bytes(unix.NL80211_ATTR_IE, []byte{0x7F, 0x8, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40})
			ae.Bytes(unix.NL80211_ATTR_IE_PROBE_RESP, []byte{0x7F, 0x8, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40})
			ae.Bytes(unix.NL80211_ATTR_IE_ASSOC_RESP, []byte{0x7F, 0x8, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40})

			support, err := c.CheckExtFeature(ifi, unix.NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211)
			if err != nil {
				log.Printf("checkExtFeature NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211 error - %s\n", err)
			}
			if !support {
				log.Printf("checkExtFeature NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211 NOT supported\n")
			} else {
				log.Printf("checkExtFeature NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211 supported\n")
				/*
				   l_genl_msg_append_attr(cmd, NL80211_ATTR_SOCKET_OWNER, 0, NULL);
				   		l_genl_msg_append_attr(cmd,
				   				NL80211_ATTR_CONTROL_PORT_OVER_NL80211,
				   				0, NULL);
				*/
				// ae.Flag(unix.NL80211_ATTR_SOCKET_OWNER, true)
				// ae.Flag(unix.NL80211_ATTR_CONTROL_PORT_OVER_NL80211, true)
			}
		},
	)

	return err
}

func (c *client) RegisterUnexpectedFrames(ifi *Interface) error {
	_, err := c.get(
		unix.NL80211_CMD_UNEXPECTED_FRAME,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
		},
	)

	return err
}

func (c *client) GetInterface(ifi *Interface) ([]*Interface, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_INTERFACE,
		0,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			// seems to be automatically set by the bibrary
			// ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(ifi.Index))
		},
	)
	if err != nil {
		return nil, err
	}

	intfs, err := parseInterfaces(msgs)
	if err != nil {
		log.Println(err)
	}

	return intfs, nil
}

func (c *client) SetInterfaceMode(ifi *Interface, mode uint32) error {
	_, err := c.get(
		unix.NL80211_CMD_SET_INTERFACE,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Uint32(unix.NL80211_ATTR_IFTYPE, mode)
		},
	)
	return err
}

// https://github.com/mdlayher/wifi/pull/79/commits/34d4e06d4c027d0a5a2aa851148fd1f28db1bbb0
func (c *client) TriggerScan(ifi *Interface) error {
	/*
				// TRIGGER_SCAN
						msgs, err := c.get(
							unix.NL80211_CMD_TRIGGER_SCAN,
							// netlink.Acknowledge
		netlink.Request,
							ifi,
							func(ae *netlink.AttributeEncoder) {
								ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(ifi.Index))
								ae.Nested(unix.NL80211_ATTR_SCAN_SSIDS, func(nae *netlink.AttributeEncoder) error {
									nae.Bytes(unix.NL80211_ATTR_SCHED_SCAN_MATCH_SSID, nlenc.Bytes(""))
									return nil
								})
							},
						)
						if err != nil {
							log.Printf("netlink NL80211_CMD_TRIGGER_SCAN failed - %s\n", err)
							return
						}

						log.Printf("netlink NL80211_CMD_TRIGGER_SCAN num messages returned - %d\n", len(msgs))

						for _, m := range msgs {
							if m.Header.Version != c.familyVersion {
								log.Printf("************* SCAN INVALID FAMILY")
								continue
							}
							if m.Header.Command == unix.NL80211_CMD_SCAN_ABORTED {
								log.Printf("************* SCAN ABORTED")
								return
							}
							if m.Header.Command == unix.NL80211_CMD_NEW_SCAN_RESULTS {
								log.Printf("*************NEW SCAN RESULTS")
								break
							}

							log.Printf("*************NOTHING NOTHING")
						}
	*/
	_, err := c.get(
		unix.NL80211_CMD_TRIGGER_SCAN,
		netlink.Acknowledge,
		ifi,
		nil,
	)
	if err != nil {
		return err
	}

	/*
		// wait for kernel to inform the scan status
		if status := <-informer; status == scan_abort {
			return errors.New("NL80211 Scan aborted by kernel")
		}
	*/
	log.Printf("SCAN TRIGGERED\n")

	return nil
}

// checkExtFeature Checks if a physical interface supports a extended feature
func (c *client) CheckExtFeature(ifi *Interface, feature uint) (bool, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_WIPHY,
		netlink.Dump,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Flag(unix.NL80211_ATTR_SPLIT_WIPHY_DUMP, true)
		},
	)
	if err != nil {
		return false, err
	}

	var features []byte
found:
	for i := range msgs {
		attrs, err := netlink.UnmarshalAttributes(msgs[i].Data)
		if err != nil {
			return false, err
		}
		for _, a := range attrs {
			if a.Type == unix.NL80211_ATTR_EXT_FEATURES {
				features = a.Data
				break found
			}
		}
	}

	if feature/8 >= uint(len(features)) {
		return false, nil
	}

	return (features[feature/8]&(1<<(feature%8)) != 0), nil
}

func (c *client) RegisterFrame(ifi *Interface, frameType uint16, frameMatch []byte) error {
	_, err := c.get(
		unix.NL80211_CMD_REGISTER_FRAME,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Uint16(unix.NL80211_ATTR_FRAME_TYPE, frameType)
			ae.Bytes(unix.NL80211_ATTR_FRAME_MATCH, frameMatch)
		},
	)
	if err != nil {
		return err
	}

	return nil
}

// AllBSS requests that nl80211 return all the BSS around the specified Interface.
func (c *client) AllBSS(ifi *Interface) ([]*BSS, error) {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_SCAN,
		netlink.Dump,
		ifi,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return parseAllBSS(msgs)
}

// parseAllBSS parses all the BSS from nl80211 BSS messages
func parseAllBSS(msgs []genetlink.Message) ([]*BSS, error) {
	fmt.Println(len(msgs))
	all_bss := make([]*BSS, 0, len(msgs))
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return nil, err
		}

		var bss BSS
		for _, a := range attrs {
			if a.Type != unix.NL80211_ATTR_BSS {
				continue
			}

			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return nil, err
			}

			if !attrsContain(nattrs, unix.NL80211_BSS_STATUS) {
				bss.Status = BSSStatusDisAssociated
			}

			if err := (&bss).parseAttributes(nattrs); err != nil {
				continue
			}
		}
		all_bss = append(all_bss, &bss)
	}
	return all_bss, nil
}

/*
< Request: Set Wiphy (0x02) len 56 [ack]                                                                                                                                                                   897.494534
    Interface Index: 6 (0x00000006)
    Wiphy TXQ Parameters: len 44
        2c 00 01 80 05 00 01 00 00 00 00 00 06 00 02 00  ,...............
        2f 00 00 00 06 00 03 00 03 00 00 00 06 00 04 00  /...............
        07 00 00 00 05 00 05 00 01 00 00 00              ............

< Request: Set Wiphy (0x02) len 56 [ack]                                                                                                                                                                    12.075553
    Interface Index: 6 (0x00000006)
    Wiphy TXQ Parameters: len 44
        2c 00 01 80 05 00 01 00 00 00 00 00 06 00 02 00  ,...............
        2f 00 00 00 06 00 03 00 03 00 00 00 06 00 04 00  /...............
        07 00 00 00 05 00 05 00 01 00 00 00              ............

< Request: Set Wiphy (0x02) len 56 [ack]                                                                                                                                                                    12.075815
    Interface Index: 6 (0x00000006)
    Wiphy TXQ Parameters: len 44
        2c 00 01 80 05 00 01 00 01 00 00 00 06 00 02 00  ,...............
        5e 00 00 00 06 00 03 00 07 00 00 00 06 00 04 00  ^...............
        0f 00 00 00 05 00 05 00 01 00 00 00              ............

< Request: Set Wiphy (0x02) len 56 [ack]                                                                                                                                                                    12.076043
    Interface Index: 6 (0x00000006)
    Wiphy TXQ Parameters: len 44
        2c 00 01 80 05 00 01 00 02 00 00 00 06 00 02 00  ,...............
        00 00 00 00 06 00 03 00 0f 00 00 00 06 00 04 00  ................
        3f 00 00 00 05 00 05 00 03 00 00 00              ?...........

< Request: Set Wiphy (0x02) len 56 [ack]                                                                                                                                                                    12.076247
    Interface Index: 6 (0x00000006)
    Wiphy TXQ Parameters: len 44
        2c 00 01 80 05 00 01 00 03 00 00 00 06 00 02 00  ,...............
        00 00 00 00 06 00 03 00 0f 00 00 00 06 00 04 00  ................
        ff 03 00 00 05 00 05 00 07 00 00 00              ............


*/

func (c *client) SetTXQParams(ifi *Interface, queue uint8, aifs uint8, cw_min, cw_max, burst_time uint16) error {
	_, err := c.get(
		unix.NL80211_CMD_SET_WIPHY,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Nested(unix.NL80211_ATTR_WIPHY_TXQ_PARAMS, func(nae *netlink.AttributeEncoder) error {

				/* We are only sending parameters for a single TXQ at a time */
				nae.Nested(1, func(nnae *netlink.AttributeEncoder) error {
					nnae.Uint8(unix.NL80211_TXQ_ATTR_QUEUE, queue)

					nnae.Uint16(unix.NL80211_TXQ_ATTR_TXOP, (burst_time*100+16)/32)
					nnae.Uint16(unix.NL80211_TXQ_ATTR_CWMIN, cw_min)
					nnae.Uint16(unix.NL80211_TXQ_ATTR_CWMAX, cw_max)

					nnae.Uint8(unix.NL80211_TXQ_ATTR_AIFS, aifs)
					return nil
				})
				return nil
			})
		},
	)

	return err
}

/*
< Request: Set BSS (0x19) len 48 [ack]                                                                                                                                                                       7.998623

	Interface Index: 6 (0x00000006)
	BSS CTS Protection: 0 (0x00)
	BSS Short Preamble: 0 (0x00)
	BSS HT Operation Mode: 0 (0x0000)
	AP Isolate: 0 (0x00)
	BSS Basic Rates: len 3
	    0c 18 30
*/
func (c *client) SetBSS(ifi *Interface) error {
	_, err := c.get(
		unix.NL80211_CMD_SET_BSS,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Uint8(unix.NL80211_ATTR_BSS_CTS_PROT, 0x0)
			ae.Uint8(unix.NL80211_ATTR_BSS_SHORT_PREAMBLE, 0x0)
			ae.Uint8(unix.NL80211_ATTR_BSS_SHORT_SLOT_TIME, 0x1)
			ae.Uint8(unix.NL80211_ATTR_AP_ISOLATE, 0x0)
			// ae.Uint32(unix.NL80211_ATTR_BSS_BASIC_RATES, 0x160b0402) //  02 04 0b 16  // 2.4GHz only

			ae.Bytes(unix.NL80211_ATTR_BSS_BASIC_RATES, []byte{0x0C, 0x18, 0x30}) //  0x0C, 0x18, 0x30  // 5GHz only
			ae.Uint16(unix.NL80211_ATTR_BSS_HT_OPMODE, 0x0)                       // 5GHz only
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (c *client) SetMulticastToUnicast(ifi *Interface) error {
	_, err := c.get(
		unix.NL80211_CMD_SET_MULTICAST_TO_UNICAST,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			// ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(ifi.Index))
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (c *client) RegisterBeacons(ifi *Interface) error {
	_, err := c.get(
		unix.NL80211_CMD_REGISTER_BEACONS,
		netlink.Acknowledge,
		nil,
		func(ae *netlink.AttributeEncoder) {
			ae.Uint32(unix.NL80211_ATTR_WIPHY, 0x0)
		},
	)
	if err != nil {
		return err
	}

	return nil
}

/*
< Request: Set Wiphy (0x02) len 32 [ack]                                                                                                                                                                     7.986746
    Interface Index: 6 (0x00000006)
    Wiphy Frequency: 5200 (0x00001450)
    Channel Width: 3 (0x00000003)
    Center Frequency 1: 5210 (0x0000145a)
*/

func (c *client) SetWiPhy(ifi *Interface, freq, centreFreq, width uint32) error {
	_, err := c.get(
		unix.NL80211_CMD_SET_WIPHY,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Uint32(unix.NL80211_ATTR_WIPHY_FREQ, freq)
			ae.Uint32(unix.NL80211_ATTR_CHANNEL_WIDTH, width)
			ae.Uint32(unix.NL80211_ATTR_CENTER_FREQ1, centreFreq)
			// ae.Uint32(unix.NL80211_ATTR_WIPHY_CHANNEL_TYPE, 0x0) // deprecated
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (c *client) GetWiPhy(ifi *Interface) error {
	msgs, err := c.get(
		unix.NL80211_CMD_GET_WIPHY,
		netlink.Dump,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Flag(unix.NL80211_ATTR_SPLIT_WIPHY_DUMP, true)
		},
	)
	if err != nil {
		return err
	}

	log.Printf("Printing MULTICAST Groups\n")
	for _, v := range c.groups {
		log.Printf("%s - %d\n", v.Name, v.ID)
	}

	log.Printf("these many messages recvd: %d\n", len(msgs))

	// stations := make([]*StationInfo, len(msgs))
	for i := range msgs {
		if _, err = parseWiPhyInfo(msgs[i].Data); err != nil {
			log.Println(err)
		}
	}

	return nil
}

// https://gist.github.com/chrizchow/a507b3a70558672b99c814f80314baff
func parseWiPhyInfo(b []byte) (*StationInfo, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}

	log.Printf("these many attrs recvd: %d\n", len(attrs))

	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_ATTR_CIPHER_SUITES:
			log.Printf("cipher len: %d\n", len(a.Data))

			for i := 0; i < (len(a.Data) / 4); i++ {
				c := a.Data[i:(i + 4)]
				log.Printf("Supported Cipher: %s\n", hex.EncodeToString(c))
			}
		case unix.NL80211_ATTR_WIPHY_NAME:
			log.Printf("************************** WIPHY name - %s\n", string(a.Data))
		case unix.NL80211_ATTR_AKM_SUITES:
			log.Printf("************************** AKM Suites found")
		}
	}

	// No station info found
	return nil, os.ErrNotExist
}

// ADDITIONS END
//********************************

// parseInterfaces parses zero or more Interfaces from nl80211 interface
// messages.
func parseInterfaces(msgs []genetlink.Message) ([]*Interface, error) {
	ifis := make([]*Interface, 0, len(msgs))
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return nil, err
		}

		var ifi Interface
		if err := (&ifi).parseAttributes(attrs); err != nil {
			return nil, err
		}

		ifis = append(ifis, &ifi)
	}

	return ifis, nil
}

// encode provides an encoding function for ifi's attributes. If ifi is nil,
// encode is a no-op.
func (ifi *Interface) encode(ae *netlink.AttributeEncoder) {
	if ifi == nil {
		return
	}

	// Mandatory.
	ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(ifi.Index))
}

// idAttrs returns the netlink attributes required from an Interface to retrieve
// more data about it.
func (ifi *Interface) idAttrs() []netlink.Attribute {
	return []netlink.Attribute{
		{
			Type: unix.NL80211_ATTR_IFINDEX,
			Data: nlenc.Uint32Bytes(uint32(ifi.Index)),
		},
		{
			Type: unix.NL80211_ATTR_MAC,
			Data: ifi.HardwareAddr,
		},
	}
}

// parseAttributes parses netlink attributes into an Interface's fields.
func (ifi *Interface) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_ATTR_IFINDEX:
			ifi.Index = int(nlenc.Uint32(a.Data))
		case unix.NL80211_ATTR_IFNAME:
			ifi.Name = nlenc.String(a.Data)
		case unix.NL80211_ATTR_MAC:
			ifi.HardwareAddr = net.HardwareAddr(a.Data)
		case unix.NL80211_ATTR_WIPHY:
			ifi.PHY = int(nlenc.Uint32(a.Data))
		case unix.NL80211_ATTR_IFTYPE:
			// NOTE: InterfaceType copies the ordering of nl80211's interface type
			// constants.  This may not be the case on other operating systems.
			ifi.Type = InterfaceType(nlenc.Uint32(a.Data))
		case unix.NL80211_ATTR_WDEV:
			ifi.Device = int(nlenc.Uint64(a.Data))
		case unix.NL80211_ATTR_WIPHY_FREQ:
			ifi.Frequency = int(nlenc.Uint32(a.Data))
		case unix.NL80211_ATTR_REG_ALPHA2:
			ifi.RegDom.Alpha2 = nlenc.String(a.Data)
		case unix.NL80211_ATTR_DFS_REGION:
			ifi.RegDom.DFSRegion = byte(a.Data[0])
		case unix.NL80211_ATTR_REG_RULES:
			ifi.RegDom.Rules = a.Data
		case unix.NL80211_ATTR_PS_STATE:
			ifi.PowerSaver = a.Data
		}
	}

	return nil
}

// parseBSS parses a single BSS with a status attribute from nl80211 BSS messages.
func parseBSS(msgs []genetlink.Message) (*BSS, error) {
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return nil, err
		}

		for _, a := range attrs {
			if a.Type != unix.NL80211_ATTR_BSS {
				continue
			}

			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return nil, err
			}

			// The BSS which is associated with an interface will have a status
			// attribute
			if !attrsContain(nattrs, unix.NL80211_BSS_STATUS) {
				continue
			}

			var bss BSS
			if err := (&bss).parseAttributes(nattrs); err != nil {
				return nil, err
			}

			return &bss, nil
		}
	}

	return nil, os.ErrNotExist
}

// parseAttributes parses netlink attributes into a BSS's fields.
func (b *BSS) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_BSS_BSSID:
			b.BSSID = net.HardwareAddr(a.Data)
		case unix.NL80211_BSS_FREQUENCY:
			b.Frequency = int(nlenc.Uint32(a.Data))
		case unix.NL80211_BSS_BEACON_INTERVAL:
			// Raw value is in "Time Units (TU)".  See:
			// https://en.wikipedia.org/wiki/Beacon_frame
			b.BeaconInterval = time.Duration(nlenc.Uint16(a.Data)) * 1024 * time.Microsecond
		case unix.NL80211_BSS_SEEN_MS_AGO:
			// * @NL80211_BSS_SEEN_MS_AGO: age of this BSS entry in ms
			b.LastSeen = time.Duration(nlenc.Uint32(a.Data)) * time.Millisecond
		case unix.NL80211_BSS_STATUS:
			// NOTE: BSSStatus copies the ordering of nl80211's BSS status
			// constants.  This may not be the case on other operating systems.
			b.Status = BSSStatus(nlenc.Uint32(a.Data))
		case unix.NL80211_BSS_INFORMATION_ELEMENTS:
			ies, err := parseIEs(a.Data)
			if err != nil {
				return err
			}

			// TODO(mdlayher): return more IEs if they end up being generally useful
			for _, ie := range ies {
				switch ie.ID {
				case ieSSID:
					b.SSID = decodeSSID(ie.Data)
				case ieBSSLoad:
					Bssload, err := decodeBSSLoad(ie.Data)
					if err != nil {
						continue // This IE is malformed
					}
					b.Load = *Bssload
				}
			}
		}
	}

	return nil
}

// parseStationInfo parses StationInfo attributes from a byte slice of
// netlink attributes.
func parseStationInfo(b []byte) (*StationInfo, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}

	var info StationInfo
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_ATTR_MAC:
			info.HardwareAddr = net.HardwareAddr(a.Data)
		case unix.NL80211_ATTR_STA_INFO:
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return nil, err
			}

			if err := (&info).parseAttributes(nattrs); err != nil {
				return nil, err
			}

			// Parsed the necessary data.
			return &info, nil
		}
	}

	// No station info found
	return nil, os.ErrNotExist
}

// parseAttributes parses netlink attributes into a StationInfo's fields.
func (info *StationInfo) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_STA_INFO_CONNECTED_TIME:
			// Though nl80211 does not specify, this value appears to be in seconds:
			// * @NL80211_STA_INFO_CONNECTED_TIME: time since the station is last connected
			info.Connected = time.Duration(nlenc.Uint32(a.Data)) * time.Second
		case unix.NL80211_STA_INFO_INACTIVE_TIME:
			// * @NL80211_STA_INFO_INACTIVE_TIME: time since last activity (u32, msecs)
			info.Inactive = time.Duration(nlenc.Uint32(a.Data)) * time.Millisecond
		case unix.NL80211_STA_INFO_RX_BYTES64:
			info.ReceivedBytes = int(nlenc.Uint64(a.Data))
		case unix.NL80211_STA_INFO_TX_BYTES64:
			info.TransmittedBytes = int(nlenc.Uint64(a.Data))
		case unix.NL80211_STA_INFO_SIGNAL:
			//  * @NL80211_STA_INFO_SIGNAL: signal strength of last received PPDU (u8, dBm)
			// Should just be cast to int8, see code here: https://git.kernel.org/pub/scm/linux/kernel/git/jberg/iw.git/tree/station.c#n378
			info.Signal = int(int8(a.Data[0]))
		case unix.NL80211_STA_INFO_SIGNAL_AVG:
			info.SignalAverage = int(int8(a.Data[0]))
		case unix.NL80211_STA_INFO_RX_PACKETS:
			info.ReceivedPackets = int(nlenc.Uint32(a.Data))
		case unix.NL80211_STA_INFO_TX_PACKETS:
			info.TransmittedPackets = int(nlenc.Uint32(a.Data))
		case unix.NL80211_STA_INFO_TX_RETRIES:
			info.TransmitRetries = int(nlenc.Uint32(a.Data))
		case unix.NL80211_STA_INFO_TX_FAILED:
			info.TransmitFailed = int(nlenc.Uint32(a.Data))
		case unix.NL80211_STA_INFO_BEACON_LOSS:
			info.BeaconLoss = int(nlenc.Uint32(a.Data))
		case unix.NL80211_STA_INFO_RX_BITRATE, unix.NL80211_STA_INFO_TX_BITRATE:
			rate, err := parseRateInfo(a.Data)
			if err != nil {
				return err
			}

			// TODO(mdlayher): return more statistics if they end up being
			// generally useful
			switch a.Type {
			case unix.NL80211_STA_INFO_RX_BITRATE:
				info.ReceiveBitrate = rate.Bitrate
			case unix.NL80211_STA_INFO_TX_BITRATE:
				info.TransmitBitrate = rate.Bitrate
			}
		}

		// Only use 32-bit counters if the 64-bit counters are not present.
		// If the 64-bit counters appear later in the slice, they will overwrite
		// these values.
		if info.ReceivedBytes == 0 && a.Type == unix.NL80211_STA_INFO_RX_BYTES {
			info.ReceivedBytes = int(nlenc.Uint32(a.Data))
		}
		if info.TransmittedBytes == 0 && a.Type == unix.NL80211_STA_INFO_TX_BYTES {
			info.TransmittedBytes = int(nlenc.Uint32(a.Data))
		}
	}

	return nil
}

// rateInfo provides statistics about the receive or transmit rate of
// an interface.
type rateInfo struct {
	// Bitrate in bits per second.
	Bitrate int
}

// parseRateInfo parses a rateInfo from netlink attributes.
func parseRateInfo(b []byte) (*rateInfo, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}

	var info rateInfo
	for _, a := range attrs {
		switch a.Type {
		case unix.NL80211_RATE_INFO_BITRATE32:
			info.Bitrate = int(nlenc.Uint32(a.Data))
		}

		// Only use 16-bit counters if the 32-bit counters are not present.
		// If the 32-bit counters appear later in the slice, they will overwrite
		// these values.
		if info.Bitrate == 0 && a.Type == unix.NL80211_RATE_INFO_BITRATE {
			info.Bitrate = int(nlenc.Uint16(a.Data))
		}
	}

	// Scale bitrate to bits/second as base unit instead of 100kbits/second.
	// * @NL80211_RATE_INFO_BITRATE: total bitrate (u16, 100kbit/s)
	info.Bitrate *= 100 * 1000

	return &info, nil
}

// attrsContain checks if a slice of netlink attributes contains an attribute
// with the specified type.
func attrsContain(attrs []netlink.Attribute, typ uint16) bool {
	for _, a := range attrs {
		if a.Type == typ {
			return true
		}
	}

	return false
}

// decodeSSID safely parses a byte slice into UTF-8 runes, and returns the
// resulting string from the runes.
func decodeSSID(b []byte) string {
	buf := bytes.NewBuffer(nil)
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]

		buf.WriteRune(r)
	}

	return buf.String()
}

// decodeBSSLoad Decodes the BSSLoad IE. Supports Version 1 and Version 2
// values according to https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-ieee80211.c
// See also source code of iw (v5.19) scan.c Line 1634ff
// BSS Load ELement (with length 5) is defined by chapter 9.4.2.27 (page 1066) of the current IEEE 802.11-2020
func decodeBSSLoad(b []byte) (*BSSLoad, error) {
	var load BSSLoad
	if len(b) == 5 {
		// Wireshark calls this "802.11e CCA Version"
		// This is the version defined in IEEE 802.11 (Versions 2007, 2012, 2016 and 2020)
		load.Version = 2
		load.StationCount = binary.LittleEndian.Uint16(b[0:2])               // first 2 bytes
		load.ChannelUtilization = b[2]                                       // next 1 byte
		load.AvailableAdmissionCapacity = binary.LittleEndian.Uint16(b[3:5]) // last 2 bytes
	} else if len(b) == 4 {
		// Wireshark calls this "Cisco QBSS Version 1 - non CCA"
		load.Version = 1
		load.StationCount = binary.LittleEndian.Uint16(b[0:2]) // first 2 bytes
		load.ChannelUtilization = b[2]                         // next 1 byte
		load.AvailableAdmissionCapacity = uint16(b[3])         // next 1 byte
	} else {
		return nil, errInvalidBSSLoad
	}
	return &load, nil
}
