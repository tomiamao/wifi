//go:build linux
// +build linux

package wifi

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"
	"unicode/utf8"

	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
	multicastConn *genetlink.Conn
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

	// conn for multicast updates
	conn, err := genetlink.Dial(nil)
	if err != nil {
		log.Printf("netlink dial failed - %s\n", err)
		return nil, err
	}

	for _, group := range family.Groups {
		if group.Name == unix.NL80211_MULTICAST_GROUP_SCAN {
			err = conn.JoinGroup(group.ID)
			if err != nil {
				log.Printf("join group  failed - %s\n", err)
				return nil, err
			}
		} else if group.Name == unix.NL80211_MULTICAST_GROUP_MLME {
			err = conn.JoinGroup(group.ID)
			if err != nil {
				log.Printf("join group  failed - %s\n", err)
				return nil, err
			}
		} else if group.Name == unix.NL80211_MULTICAST_GROUP_REG {
			err = conn.JoinGroup(group.ID)
			if err != nil {
				log.Printf("join group  failed - %s\n", err)
				return nil, err
			}
		} else if group.Name == unix.NL80211_MULTICAST_GROUP_VENDOR {
			err = conn.JoinGroup(group.ID)
			if err != nil {
				log.Printf("join group  failed - %s\n", err)
				return nil, err
			}
		}
	}

	return &client{
		c:             c,
		multicastConn: conn,
		familyID:      family.ID,
		familyVersion: family.Version,
		groups:        family.Groups,
	}, nil
}

// Close closes the client's generic netlink connection.
func (c *client) Close() error { return c.c.Close() }

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
	support, err := c.checkExtFeature(ifi, unix.NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK)
	if err != nil {
		log.Printf("checkExtFeature NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK not supported\n")
		return err
	}
	if !support {
		log.Printf("NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK not supported\n")
		// return errNotSupported
		return fmt.Errorf("errNotSupported")
	}

	support, err = c.checkExtFeature(ifi, unix.NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X)
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

	// Note: don't send netlink.Acknowledge or we get an extra message back from
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

// *******************************
// ADDITIONS START

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
			ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(ifi.Index))
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
	if err != nil {
		return err
	}

	return nil
}

func (c *client) StartMulticastProcessing() {
	go c.processMulticastEvents()
}

// register multicast event
func (c *client) RegisterMulticastGroup(grp string) error {
	for _, group := range c.groups {
		if group.Name == grp {
			err := c.multicastConn.JoinGroup(group.ID)
			if err != nil {
				log.Printf("join group  failed - %s\n", err)
				return err
			}
			return nil
		}
	}
	return nil
}

func checkLayers(p gopacket.Packet, want []gopacket.LayerType) {
	layers := p.Layers()
	log.Println("Checking packet layers, want", want)
	for _, l := range layers {
		log.Printf("  Got layer %v, %d bytes, payload of %d bytes", l.LayerType(),
			len(l.LayerContents()), len(l.LayerPayload()))
	}
	log.Printf("%v\n", p)
}

func (c *client) processMulticastEvents() {
	for {
		genl_msgs, _, err := c.multicastConn.Receive()
		if err != nil {
			log.Printf("netlink multicast event receive failed - %s\n", err)
			return
		}
		for _, msg := range genl_msgs {
			switch msg.Header.Command {
			case unix.NL80211_CMD_START_AP:
				log.Printf("MULTICAST EVENT RECEIVED - NL80211_CMD_START_AP\n")
				continue
			case unix.NL80211_CMD_TRIGGER_SCAN:
				log.Printf("MULTICAST EVENT RECEIVED - NL80211_CMD_TRIGGER_SCAN\n")
				continue
			case unix.NL80211_CMD_SCAN_ABORTED:
				log.Printf("MULTICAST EVENT RECEIVED - NL80211_CMD_SCAN_ABORTED\n")
				continue
			case unix.NL80211_CMD_NEW_SCAN_RESULTS:
				log.Printf("MULTICAST EVENT RECEIVED - NL80211_CMD_NEW_SCAN_RESULTS\n")
				continue
			case unix.NL80211_CMD_SCHED_SCAN_STOPPED:
				log.Printf("MULTICAST EVENT RECEIVED - NL80211_CMD_SCHED_SCAN_STOPPED\n")
				continue
			case unix.NL80211_CMD_AUTHENTICATE:
				log.Printf("MULTICAST EVENT RECEIVED - NL80211_CMD_AUTHENTICATE\n")
				// extract params

				/*
					attrs, err := netlink.UnmarshalAttributes(msg.Data)
					if err != nil {
						log.Printf("processMulticastEvents() NL80211_CMD_AUTHENTICATE error I - %s\n", err)
						continue
					}
				*/

				ad, err := netlink.NewAttributeDecoder(msg.Data)
				if err != nil {
					log.Printf("processMulticastEvents() NL80211_CMD_AUTHENTICATE failed to decode attributes I - %s\n", err)
					continue
				}

				// Return a nil slice when there are no attributes to decode.
				if ad.Len() == 0 {
					log.Printf("processMulticastEvents() NL80211_CMD_AUTHENTICATE No attributes found\n")
					continue
				}

				log.Printf("processMulticastEvents() NL80211_CMD_AUTHENTICATE number of attributes found - %d\n", ad.Len())

				// attrs := make([]netlink.Attribute, 0, ad.Len())

				for ad.Next() {
					aType := ad.Type()

					if aType == unix.NL80211_ATTR_MAC {
						log.Printf("NL80211_CMD_AUTHENTICATE ATTR_MAC found\n")
					} else if aType == unix.NL80211_ATTR_FRAME {

						aData := ad.Bytes()

						log.Printf("NL80211_CMD_AUTHENTICATE ATTR_FRAME found actual len - %d\n", len(aData))

						if len(aData) == 0 {
							log.Printf("NL80211_CMD_AUTHENTICATE ATTR_FRAME no data present\n")
							continue
						}

						// parse 802.11 mgmt frame
						p := gopacket.NewPacket(aData, layers.LinkTypeIEEE802_11, gopacket.NoCopy)

						checkLayers(p, []gopacket.LayerType{layers.LayerTypeDot11})

						if got, ok := p.Layer(layers.LayerTypeDot11).(*layers.Dot11); ok {
							log.Printf("802.11 packet processed successfully - %v\n", got.Address1)
						}

						log.Println(hex.EncodeToString(aData[24:26]))
						log.Println(hex.EncodeToString(aData[26:28]))
						log.Println(hex.EncodeToString(aData[28:30]))

						d := &layers.Dot11MgmtAuthentication{}

						d.DecodeFromBytes(aData[24:], gopacket.NilDecodeFeedback)

						log.Printf("************ %s - %d - %s", d.Algorithm, d.Sequence, d.Status)

						if d.Status == layers.Dot11StatusSuccess && d.Sequence == 2 && d.Algorithm == layers.Dot11AlgorithmOpen {
							log.Printf("***** successful authentication....proceeding to association\n")
						}

					} else if aType == unix.NL80211_ATTR_TIMED_OUT {
						log.Printf("NL80211_CMD_AUTHENTICATE ATTR_TIMED_OUT found\n")
					} else if aType == unix.NL80211_ATTR_WIPHY_FREQ {
						log.Printf("NL80211_CMD_AUTHENTICATE NL80211_ATTR_WIPHY_FREQ found\n")
					} else if aType == unix.NL80211_ATTR_ACK {
						log.Printf("NL80211_CMD_AUTHENTICATE NL80211_ATTR_ACK found\n")
					} else if aType == unix.NL80211_ATTR_COOKIE {
						log.Printf("NL80211_CMD_AUTHENTICATE NL80211_ATTR_COOKIE found\n")
					} else if aType == unix.NL80211_ATTR_RX_SIGNAL_DBM {
						log.Printf("NL80211_CMD_AUTHENTICATE NL80211_ATTR_RX_SIGNAL_DBM found\n")
					} else if aType == unix.NL80211_ATTR_STA_WME {
						log.Printf("NL80211_CMD_AUTHENTICATE NL80211_ATTR_STA_WME found\n")
					}
				}

				if err := ad.Err(); err != nil {
					log.Printf("processMulticastEvents() NL80211_CMD_AUTHENTICATE attribute deocde error - %s\n", err)
					continue
				}

				continue
			case unix.NL80211_CMD_ASSOCIATE:
				log.Printf("MULTICAST EVENT RECEIVED - NL80211_CMD_ASSOCIATE\n")
				// extract params
				attrs, err := netlink.UnmarshalAttributes(msg.Data)
				if err != nil {
					log.Printf("processMulticastEvents() NL80211_CMD_ASSOCIATE error I - %s\n", err)
					continue
				}

				for _, a := range attrs {
					if a.Type == unix.NL80211_ATTR_MAC {
						log.Printf("NL80211_CMD_ASSOCIATE ATTR_MAC found\n")
					} else if a.Type == unix.NL80211_ATTR_FRAME {
						log.Printf("NL80211_CMD_ASSOCIATE ATTR_FRAME found\n")

						if len(a.Data) == 0 {
							log.Printf("NL80211_CMD_ASSOCIATE ATTR_FRAME no data present\n")
							continue
						}

						// parse 802.11 mgmt frame
						p := gopacket.NewPacket(a.Data, layers.LinkTypeIEEE802_11, gopacket.NoCopy)

						checkLayers(p, []gopacket.LayerType{layers.LayerTypeDot11})

						if got, ok := p.Layer(layers.LayerTypeDot11).(*layers.Dot11); ok {

							log.Printf("802.11 packet processed successfully - %v\n", got.Address1)

						}

					} else if a.Type == unix.NL80211_ATTR_TIMED_OUT {
						log.Printf("NL80211_CMD_ASSOCIATE ATTR_TIMED_OUT found\n")
					} else if a.Type == unix.NL80211_ATTR_WIPHY_FREQ {
						log.Printf("NL80211_CMD_ASSOCIATE NL80211_ATTR_WIPHY_FREQ found\n")
					} else if a.Type == unix.NL80211_ATTR_ACK {
						log.Printf("NL80211_CMD_ASSOCIATE NL80211_ATTR_ACK found\n")
					} else if a.Type == unix.NL80211_ATTR_COOKIE {
						log.Printf("NL80211_CMD_ASSOCIATE NL80211_ATTR_COOKIE found\n")
					} else if a.Type == unix.NL80211_ATTR_RX_SIGNAL_DBM {
						log.Printf("NL80211_CMD_ASSOCIATE NL80211_ATTR_RX_SIGNAL_DBM found\n")
					} else if a.Type == unix.NL80211_ATTR_STA_WME {
						log.Printf("NL80211_CMD_ASSOCIATE NL80211_ATTR_STA_WME found\n")
					}
				}
				continue
			case unix.NL80211_CMD_DEAUTHENTICATE:
				log.Printf("MULTICAST EVENT RECEIVED - NL80211_CMD_DEAUTHENTICATE\n")
				continue
			case unix.NL80211_CMD_DISASSOCIATE:
				log.Printf("MULTICAST EVENT RECEIVED - NL80211_CMD_DISASSOCIATE\n")
				continue
			case unix.NL80211_CMD_FRAME_TX_STATUS:
				log.Printf("MULTICAST EVENT RECEIVED - NL80211_CMD_FRAME_TX_STATUS\n")
				continue
			case unix.NL80211_CMD_FRAME:
				log.Printf("MULTICAST EVENT RECEIVED - NL80211_CMD_FRAME\n")

				attrs, err := netlink.UnmarshalAttributes(msg.Data)
				if err != nil {
					log.Printf("processMulticastEvents() NL80211_CMD_FRAME error I - %s\n", err)
					continue
				}

				for _, a := range attrs {
					if a.Type == unix.NL80211_ATTR_MAC {
						log.Printf("NL80211_CMD_ASSOCIATE ATTR_MAC found\n")
					} else if a.Type == unix.NL80211_ATTR_FRAME {
						log.Printf("NL80211_CMD_ASSOCIATE ATTR_FRAME found\n")
					}
				}
				continue
			case unix.NL80211_CMD_CONNECT:
				log.Printf("MULTICAST EVENT RECEIVED - NL80211_CMD_CONNECT\n")

				attrs, err := netlink.UnmarshalAttributes(msg.Data)
				if err != nil {
					log.Printf("processMulticastEvents() NL80211_CMD_CONNECT error I - %s\n", err)
					continue
				}

				for _, a := range attrs {
					if a.Type == unix.NL80211_ATTR_MAC {
						log.Printf("NL80211_CMD_CONNECT ATTR_MAC found\n")
					} else if a.Type == unix.NL80211_ATTR_FRAME {
						log.Printf("NL80211_CMD_CONNECT ATTR_FRAME found\n")
					}
				}
				continue
			}
		}
	}
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

func ChannelToFreq2Ghz(channel int) int {
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
	SeqCtlr  uint16 // len 2
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
func (b *BeaconHead) AppendSupportedRateIE(mandatory bool, rateMbps uint) error {
	if b.SupportedRates == nil {
		b.SupportedRates = make([]byte, 0)
	}

	var mandatoryBit byte = 0
	if mandatory {
		mandatoryBit = 0x10
	}
	val := mandatoryBit | byte(rateMbps*2)

	if len(b.SupportedRates) > 1 && len(b.SupportedRates) < 3 {
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
	b.DSParamSet = append(b.SSID, 0x3, 0x1, channel) // element ID, length, channel
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

	data = append(data, b.SupportedRates...)
	data = append(data, b.DSParamSet...)

	return data
}

type BeaconTail struct {
	ERP                    []byte
	ExtendedSupportedRates []byte
}

func (b *BeaconTail) SetERPIE() error {
	b.ERP = make([]byte, 0)
	b.ERP = append(b.ERP, 0x2A, 0x1, 0x4) // element ID, length, set Barker Preamble mode
	return nil
}

// rate in Mbps
func (b *BeaconTail) AppendExtendedSupportedRateIE(mandatory bool, rateMbps uint) error {
	if b.ExtendedSupportedRates == nil {
		b.ExtendedSupportedRates = make([]byte, 0)
	}

	var mandatoryBit byte = 0
	if mandatory {
		mandatoryBit = 0x10
	}
	val := mandatoryBit | byte(rateMbps*2)

	if len(b.ExtendedSupportedRates) > 1 && len(b.ExtendedSupportedRates) < 3 {
		return fmt.Errorf("invalid supported rate filed")
	}
	if len(b.ExtendedSupportedRates) == 0 { // no previous supported rates configured
		b.ExtendedSupportedRates = append(b.ExtendedSupportedRates, 0x1, 0x1, val) // element ID, length
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

// use channel 6 in the 2.4GHz spectrum - specify 6 for freqChannel
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
				CapabilityInfo: 0x411, // bits set: ESS, Short Slot time
			}
			(&beaconHead).SetSSIDIE(ssid)
			(&beaconHead).AppendSupportedRateIE(true, 1)   // madatory 1Mbps
			(&beaconHead).AppendSupportedRateIE(true, 2)   // madatory 2Mbps
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
			ae.Bytes(unix.NL80211_ATTR_BEACON_TAIL, beaconTail.Serialize())

			ae.Bytes(unix.NL80211_ATTR_SSID, []byte(ssid))
			ae.Uint32(unix.NL80211_ATTR_HIDDEN_SSID, uint32(unix.NL80211_HIDDEN_SSID_NOT_IN_USE))

			ae.Uint32(unix.NL80211_ATTR_BEACON_INTERVAL, uint32(100)) // 100 TU  ==> 102.4ms

			// About TIM & DTIM ----> https://community.arubanetworks.com/blogs/gstefanick1/2016/01/25/80211-tim-and-dtim-information-elements
			ae.Uint32(unix.NL80211_ATTR_DTIM_PERIOD, uint32(2)) // A DTIM period field of 2 indicates every 2nd beacon is a DTIM.

			ae.Uint32(unix.NL80211_ATTR_AUTH_TYPE, unix.NL80211_AUTHTYPE_OPEN_SYSTEM)

			// ae.Flag(unix.NL80211_ATTR_PRIVACY, true)

			// TODO: figure out what these values mean
			ae.Bytes(unix.NL80211_ATTR_IE, []byte{0x7F, 0x08, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40})
			ae.Bytes(unix.NL80211_ATTR_IE_PROBE_RESP, []byte{0x7F, 0x08, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40})
			ae.Bytes(unix.NL80211_ATTR_IE_ASSOC_RESP, []byte{0x7F, 0x08, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40})
		},
	)

	return err
}

func (c *client) SetBeacon(ifi *Interface, ssid string, freqChannel byte) error {
	return c.StartAP(ifi, ssid, freqChannel)
	/*
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
					CapabilityInfo: 0x411, // bits set: ESS, Short Slot time
				}
				(&beaconHead).SetSSIDIE(ssid)
				(&beaconHead).AppendSupportedRateIE(true, 1)   // madatory 1Mbps
				(&beaconHead).AppendSupportedRateIE(true, 2)   // madatory 2Mbps
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
				ae.Bytes(unix.NL80211_ATTR_BEACON_TAIL, beaconTail.Serialize())

				ae.Bytes(unix.NL80211_ATTR_SSID, []byte(ssid))
				ae.Uint32(unix.NL80211_ATTR_HIDDEN_SSID, uint32(unix.NL80211_HIDDEN_SSID_NOT_IN_USE))

				ae.Uint32(unix.NL80211_ATTR_BEACON_INTERVAL, uint32(100)) // 100 TU  ==> 102.4ms

				// About TIM & DTIM ----> https://community.arubanetworks.com/blogs/gstefanick1/2016/01/25/80211-tim-and-dtim-information-elements
				ae.Uint32(unix.NL80211_ATTR_DTIM_PERIOD, uint32(2)) // A DTIM period field of 2 indicates every 2nd beacon is a DTIM.

				// ae.Uint32(unix.NL80211_ATTR_AUTH_TYPE, unix.NL80211_AUTHTYPE_OPEN_SYSTEM)

				// ae.Flag(unix.NL80211_ATTR_PRIVACY, true)

				// TODO: figure out what these values mean
				ae.Bytes(unix.NL80211_ATTR_IE, []byte{0x7F, 0x08, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40})
				ae.Bytes(unix.NL80211_ATTR_IE_PROBE_RESP, []byte{0x7F, 0x08, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40})
				ae.Bytes(unix.NL80211_ATTR_IE_ASSOC_RESP, []byte{0x7F, 0x08, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40})
			},
		)

		return err
	*/
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

/*
func (c *client) SetInterfaceToAPMode(ifi *Interface) error {
	_, err := c.get(
		unix.NL80211_CMD_SET_INTERFACE,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			// ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(ifi.Index))
			ae.Uint32(unix.NL80211_ATTR_IFTYPE, unix.NL80211_IFTYPE_AP)
		},
	)
	if err != nil {
		return err
	}

	return nil
}
*/

func (c *client) SetInterfaceMode(ifi *Interface, mode uint32) error {
	_, err := c.get(
		unix.NL80211_CMD_SET_INTERFACE,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Uint32(unix.NL80211_ATTR_IFTYPE, mode)
		},
	)
	if err != nil {
		return err
	}

	return nil
}

// https://github.com/mdlayher/wifi/pull/79/commits/34d4e06d4c027d0a5a2aa851148fd1f28db1bbb0
func (c *client) TriggerScan(ifi *Interface) error {
	/*
		// TRIGGER_SCAN
				msgs, err := c.get(
					unix.NL80211_CMD_TRIGGER_SCAN,
					netlink.Acknowledge,
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
func (c *client) checkExtFeature(ifi *Interface, feature uint) (bool, error) {
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
			ae.Uint32(unix.NL80211_ATTR_BSS_BASIC_RATES, 0x160b0402)
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
			ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(ifi.Index))
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
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Uint32(unix.NL80211_ATTR_WIPHY, 0x0)
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (c *client) SetWiPhy(ifi *Interface, freq uint32) error {
	_, err := c.get(
		unix.NL80211_CMD_SET_WIPHY,
		netlink.Acknowledge,
		ifi,
		func(ae *netlink.AttributeEncoder) {
			ae.Uint32(unix.NL80211_ATTR_IFINDEX, uint32(ifi.Index))
			ae.Uint32(unix.NL80211_ATTR_WIPHY_FREQ, freq)
			ae.Uint32(unix.NL80211_ATTR_WIPHY_CHANNEL_TYPE, 0x0)
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
