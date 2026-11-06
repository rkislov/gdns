// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
)

// A TLS LDAP wire fixture exercises the real client, certificate validation,
// search encoding and separate service/user binds, including StartTLS.
func directoryFixture(t *testing.T, startTLS bool, entries int, username string) LDAP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "LDAP test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if !startTLS {
					conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
				}
				serviceBound := false
				for {
					packet, err := ber.ReadPacket(conn)
					if err != nil {
						return
					}
					if len(packet.Children) < 2 {
						return
					}
					messageID := packet.Children[0].Value.(int64)
					request := packet.Children[1]
					send := func(p *ber.Packet) {
						outer := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
						outer.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, ""))
						outer.AppendChild(p)
						conn.Write(outer.Bytes())
					}
					result := func(tag ber.Tag, code int) {
						p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
						p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
						p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
						p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
						send(p)
					}
					switch request.Tag {
					case ldap.ApplicationExtendedRequest:
						result(ldap.ApplicationExtendedResponse, 0)
						conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
					case ldap.ApplicationBindRequest:
						dn := request.Children[1].Value.(string)
						pw := string(request.Children[2].Data.Bytes())
						code := 49
						if dn == "uid=svc,dc=example,dc=org" && pw == "service-secret" {
							serviceBound = true
							code = 0
						}
						if serviceBound && dn == "uid=user,dc=example,dc=org" && pw == "correct-password" {
							code = 0
						}
						result(ldap.ApplicationBindResponse, code)
					case ldap.ApplicationSearchRequest:
						filter := request.Children[6]
						// Special characters must remain a single equality value, never filter syntax.
						if filter.Tag != 3 || string(filter.Children[1].Data.Bytes()) != username {
							t.Errorf("unexpected escaped LDAP filter: %v", filter)
							return
						}
						for i := 0; i < entries; i++ {
							p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "")
							p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid=user,dc=example,dc=org", ""))
							attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
							attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
							attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "memberOf", ""))
							values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
							values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn=dhcp,dc=example,dc=org", ""))
							attr.AppendChild(values)
							attrs.AppendChild(attr)
							p.AppendChild(attrs)
							send(p)
						}
						result(ldap.ApplicationSearchResultDone, 0)
					case ldap.ApplicationUnbindRequest:
						return
					default:
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done; wg.Wait() })
	scheme := "ldaps"
	if startTLS {
		scheme = "ldap"
	}
	return LDAP{Enabled: true, URL: scheme + "://" + listener.Addr().String(), StartTLS: startTLS, CAFile: ca, BindDN: "uid=svc,dc=example,dc=org", BindPassword: "service-secret", BaseDN: "dc=example,dc=org", UserFilter: "(uid={username})", TimeoutSeconds: 2}
}

func TestDirectoryTLSAuthentication(t *testing.T) {
	for _, startTLS := range []bool{false, true} {
		t.Run(map[bool]string{false: "LDAPS", true: "StartTLS"}[startTLS], func(t *testing.T) {
			user := "a*)(uid=*)"
			cfg := directoryFixture(t, startTLS, 1, user)
			pw := "correct-password"
			groups, err := Directory(context.Background(), cfg, user, &pw)
			require.NoError(t, err)
			require.Equal(t, []string{"cn=dhcp,dc=example,dc=org"}, groups)
			pw = "wrong"
			_, err = Directory(context.Background(), cfg, user, &pw)
			require.ErrorIs(t, err, ErrBadCredentials)
			pw = ""
			_, err = Directory(context.Background(), cfg, user, &pw)
			require.ErrorIs(t, err, ErrBadCredentials)
			groups, err = Directory(context.Background(), cfg, user, nil)
			require.NoError(t, err)
			require.Len(t, groups, 1)
			cfg.CAFile = ""
			_, err = Directory(context.Background(), cfg, user, nil)
			require.Error(t, err, "untrusted certificates must fail")
		})
	}
}
func TestDirectoryRejectsAmbiguousSearchAndPlaintext(t *testing.T) {
	for _, entries := range []int{0, 2} {
		cfg := directoryFixture(t, false, entries, "user")
		pw := "correct-password"
		_, err := Directory(context.Background(), cfg, "user", &pw)
		require.ErrorIs(t, err, ErrBadCredentials)
	}
	cfg := LDAP{Enabled: true, URL: "ldap://example.org", BindDN: "svc", BindPassword: "pw", BaseDN: "dc=org", UserFilter: "(uid={username})"}
	require.Error(t, ValidateLDAP(cfg))
	cfg.StartTLS = true
	require.NoError(t, ValidateLDAP(cfg))
	cfg.UserFilter = "(uid=*)"
	require.Error(t, ValidateLDAP(cfg))
}
