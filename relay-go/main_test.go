package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func dialTestWS(t *testing.T, url string, headers http.Header) (net.Conn, *bufio.Reader) {
	t.Helper()
	addr := strings.TrimPrefix(url, "http://")
	idx := strings.Index(addr, "/")
	hostPort := addr[:idx]
	path := addr[idx:]

	conn, err := net.DialTimeout("tcp", hostPort, 3*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", hostPort, err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var keyBytes [16]byte
	_, _ = rand.Read(keyBytes[:])
	key := base64.StdEncoding.EncodeToString(keyBytes[:])

	var req strings.Builder
	req.WriteString("GET " + path + " HTTP/1.1\r\n")
	req.WriteString("Host: " + hostPort + "\r\n")
	req.WriteString("Connection: Upgrade\r\n")
	req.WriteString("Upgrade: websocket\r\n")
	req.WriteString("Sec-WebSocket-Version: 13\r\n")
	req.WriteString("Sec-WebSocket-Key: " + key + "\r\n")
	for k, vals := range headers {
		for _, v := range vals {
			req.WriteString(k + ": " + v + "\r\n")
		}
	}
	req.WriteString("\r\n")
	if _, err := io.WriteString(conn, req.String()); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != 101 {
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}
	return conn, br
}

func writeTestMaskedFrame(t *testing.T, conn net.Conn, opcode byte, payload []byte) {
	t.Helper()
	var hdr [14]byte
	hdr[0] = 0x80 | opcode
	hlen := 2
	n := len(payload)
	switch {
	case n < 126:
		hdr[1] = 0x80 | byte(n)
	case n <= 65535:
		hdr[1] = 0x80 | 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		hlen = 4
	default:
		hdr[1] = 0x80 | 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(n))
		hlen = 10
	}
	mask := [4]byte{0x11, 0x22, 0x33, 0x44}
	copy(hdr[hlen:hlen+4], mask[:])
	hlen += 4

	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := conn.Write(hdr[:hlen]); err != nil {
		t.Fatalf("write frame header: %v", err)
	}
	if _, err := conn.Write(masked); err != nil {
		t.Fatalf("write frame payload: %v", err)
	}
}

func readTestServerFrame(t *testing.T, br *bufio.Reader) (byte, []byte) {
	t.Helper()
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			t.Fatalf("read frame header: %v", err)
		}
		opcode := hdr[0] & 0x0f
		plen := uint64(hdr[1] & 0x7f)
		if plen == 126 {
			var ext [2]byte
			_, _ = io.ReadFull(br, ext[:])
			plen = uint64(binary.BigEndian.Uint16(ext[:]))
		} else if plen == 127 {
			var ext [8]byte
			_, _ = io.ReadFull(br, ext[:])
			plen = binary.BigEndian.Uint64(ext[:])
		}
		payload := make([]byte, plen)
		if plen > 0 {
			_, _ = io.ReadFull(br, payload)
		}
		if opcode == opPing {
			continue
		}
		return opcode, payload
	}
}

func fixtureRelay(hostID string) (*relayHub, http.Header, http.Header) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	digest := sha256.Sum256([]byte(key))
	access := relayAccess{HostID: hostID, HostDigest: hex.EncodeToString(digest[:]),
		OwnerUserID: "usr-owner", OwnerTenantID: "ten-owner", WebID: "web123",
		Origin: "https://example.test"}
	host := http.Header{}
	host.Set("Dsh-Host-Registration", key)
	client := http.Header{}
	client.Set("Tiana-Caller-User-Id", access.OwnerUserID)
	client.Set("Tiana-Caller-Tenant-Id", access.OwnerTenantID)
	client.Set("Tiana-Caller-Web-Id", access.WebID)
	client.Set("Origin", access.Origin)
	return newRelayHub(access), host, client
}

func writePolicyFile(t *testing.T, path string, policy any) {
	t.Helper()
	var payload map[string]any
	if policy == nil {
		payload = map[string]any{}
	} else {
		raw, err := json.Marshal(policy)
		if err != nil {
			t.Fatalf("marshal policy: %v", err)
		}
		payload = map[string]any{
			"DSH_REMOTE_POLICY": map[string]string{
				"kind":  "plain",
				"value": string(raw),
			},
		}
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal config file: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}
}

func TestRelayHostAndClientForwarding(t *testing.T) {
	hub, hostHdr, clientHdr := fixtureRelay("mac1")
	srv := httptest.NewServer(newMux(hub))
	defer srv.Close()

	// 1. Host connects
	hostConn, hostBr := dialTestWS(t, srv.URL+"/host?host_id=mac1&name=MyMac", hostHdr)

	_, regFrame := readTestServerFrame(t, hostBr)
	if len(regFrame) < 9 || regFrame[8] != msgControlJSON {
		t.Fatalf("unexpected reg frame: %v", regFrame)
	}
	var regMsg map[string]any
	if err := json.Unmarshal(regFrame[9:], &regMsg); err != nil || regMsg["type"] != "host_registered" {
		t.Fatalf("unexpected reg msg: %s %v", regFrame[9:], err)
	}

	// 2. Client connects with Gateway identity headers
	clientConn, clientBr := dialTestWS(t, srv.URL+"/client?host_id=mac1", clientHdr)

	// Host receives open_session with gateway-verified identity
	_, openFrame := readTestServerFrame(t, hostBr)
	var openMsg map[string]any
	if err := json.Unmarshal(openFrame[9:], &openMsg); err != nil {
		t.Fatalf("decode open_session: %v", err)
	}
	if openMsg["type"] != "open_session" || openMsg["userId"] != "usr-owner" || openMsg["webId"] != "web123" {
		t.Fatalf("unexpected open_session: %+v", openMsg)
	}
	sid := uint32(openMsg["sessionId"].(float64))

	// Client receives welcome
	_, welcomeFrame := readTestServerFrame(t, clientBr)
	var welcomeMsg map[string]any
	if err := json.Unmarshal(welcomeFrame[5:], &welcomeMsg); err != nil {
		t.Fatalf("decode welcome: %v", err)
	}
	if welcomeMsg["selectedHostId"] != "mac1" || welcomeMsg["paired"] != true {
		t.Fatalf("expected mac1 selected and paired, got %+v", welcomeMsg)
	}

	// 3. Client sends multiplexed stream frame [4B streamId=7][1B type=0x10]["hello"]
	c2h := make([]byte, 5+len("hello"))
	binary.BigEndian.PutUint32(c2h[0:4], 7)
	c2h[4] = 0x10
	copy(c2h[5:], "hello")
	writeTestMaskedFrame(t, clientConn, opBinary, c2h)

	_, hostGot := readTestServerFrame(t, hostBr)
	if binary.BigEndian.Uint32(hostGot[0:4]) != sid || binary.BigEndian.Uint32(hostGot[4:8]) != 7 || string(hostGot[9:]) != "hello" {
		t.Fatalf("host received wrong frame: %v", hostGot)
	}

	// 4. Host replies [4B sid][4B streamId=7][1B type=0x13]["world"]
	h2c := make([]byte, 9+len("world"))
	binary.BigEndian.PutUint32(h2c[0:4], sid)
	binary.BigEndian.PutUint32(h2c[4:8], 7)
	h2c[8] = 0x13
	copy(h2c[9:], "world")
	writeTestMaskedFrame(t, hostConn, opBinary, h2c)

	_, clientGot := readTestServerFrame(t, clientBr)
	if binary.BigEndian.Uint32(clientGot[0:4]) != 7 || clientGot[4] != 0x13 || string(clientGot[5:]) != "world" {
		t.Fatalf("client received wrong frame: %v", clientGot)
	}
}

func TestRelayRejectsUnverifiedAdmission(t *testing.T) {
	hub, host, client := fixtureRelay("mac1")
	mux := newMux(hub)
	cases := []struct {
		name, path string
		headers    http.Header
	}{
		{"host requires registration", "/host?host_id=mac1", nil},
		{"host id is pinned", "/host?host_id=another", host},
		{"client requires verified identity", "/client", nil},
	}
	fallback := client.Clone()
	fallback.Del("Tiana-Caller-User-Id")
	fallback.Set("X-Tiana-App-Owner", "true")
	cases = append(cases, struct {
		name, path string
		headers    http.Header
	}{
		"legacy role is ignored", "/client", fallback,
	})
	duplicate := client.Clone()
	duplicate.Add("Tiana-Caller-User-Id", hub.access.OwnerUserID)
	cases = append(cases, struct {
		name, path string
		headers    http.Header
	}{
		"duplicate canonical identity is rejected", "/client", duplicate,
	})
	nonOwner := client.Clone()
	nonOwner.Set("Tiana-Caller-App-Owner-Id", "usr-someone-else")
	cases = append(cases, struct {
		name, path string
		headers    http.Header
	}{
		"mismatched app owner header is rejected", "/client", nonOwner,
	})
	for _, header := range []string{"Origin", "Tiana-Caller-User-Id", "Tiana-Caller-Tenant-Id", "Tiana-Caller-Web-Id"} {
		wrong := client.Clone()
		wrong.Del(header)
		cases = append(cases, struct {
			name, path string
			headers    http.Header
		}{header, "/client", wrong})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			r.Header = tc.headers
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("expected forbidden, got %d", w.Code)
			}
		})
	}
}

func sendTestHostControl(t *testing.T, hostConn net.Conn, obj any) {
	t.Helper()
	body, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal host control: %v", err)
	}
	frame := make([]byte, 9+len(body))
	frame[8] = msgControlJSON
	copy(frame[9:], body)
	writeTestMaskedFrame(t, hostConn, opBinary, frame)
}

func TestRelayPreAuthFloodDoesNotDisconnectHost(t *testing.T) {
	hub, hostHdr, clientHdr := fixtureRelay("mac1")
	srv := httptest.NewServer(newMux(hub))
	defer srv.Close()

	hostConn, hostBr := dialTestWS(t, srv.URL+"/host?host_id=mac1", hostHdr)
	readTestServerFrame(t, hostBr) // host_registered

	// Legitimate client connects and gets marked authenticated by Host.
	goodConn, goodBr := dialTestWS(t, srv.URL+"/client?host_id=mac1", clientHdr)
	_, openGood := readTestServerFrame(t, hostBr)
	var openGoodMsg map[string]any
	_ = json.Unmarshal(openGood[9:], &openGoodMsg)
	goodSID := uint32(openGoodMsg["sessionId"].(float64))
	if rem, ok := openGoodMsg["remainingMs"].(float64); !ok || rem <= 0 || rem > float64(maxSessionAge.Milliseconds()) {
		t.Fatalf("expected positive remainingMs in open_session, got %+v", openGoodMsg)
	}
	readTestServerFrame(t, goodBr) // welcome
	sendTestHostControl(t, hostConn, map[string]any{"type": "session_authenticated", "sessionId": goodSID})
	time.Sleep(20 * time.Millisecond)

	// Unpaired client (with valid Gateway headers) attempts a 16 KiB frame flood.
	noisyConn, noisyBr := dialTestWS(t, srv.URL+"/client?host_id=mac1", clientHdr)
	_, openNoisy := readTestServerFrame(t, hostBr)
	var openNoisyMsg map[string]any
	_ = json.Unmarshal(openNoisy[9:], &openNoisyMsg)
	noisySID := uint32(openNoisyMsg["sessionId"].(float64))
	readTestServerFrame(t, noisyBr) // welcome

	oversized := make([]byte, 16*1024)
	oversized[4] = 0x30
	writeTestMaskedFrame(t, noisyConn, opBinary, oversized)

	// Host must receive close_session for noisySID without losing its own WS!
	_, closeFrame := readTestServerFrame(t, hostBr)
	var closeMsg map[string]any
	if err := json.Unmarshal(closeFrame[9:], &closeMsg); err != nil || closeMsg["type"] != "close_session" || uint32(closeMsg["sessionId"].(float64)) != noisySID {
		t.Fatalf("expected close_session for noisy client %d, got %s", noisySID, closeFrame[9:])
	}

	// Authenticated client can still send a 16 KiB encrypted payload through the healthy Host WS.
	goodPayload := make([]byte, 5+16*1024)
	goodPayload[4] = 0x30
	writeTestMaskedFrame(t, goodConn, opBinary, goodPayload)
	_, hostGot := readTestServerFrame(t, hostBr)
	if binary.BigEndian.Uint32(hostGot[0:4]) != goodSID || len(hostGot) != 4+len(goodPayload) {
		t.Fatalf("authenticated client frame broken after noisy flood: len=%d", len(hostGot))
	}
}

func TestRelayUnauthenticatedSessionTimeout(t *testing.T) {
	hub, hostHdr, clientHdr := fixtureRelay("mac1")
	hub.unauthTimeout = 80 * time.Millisecond
	srv := httptest.NewServer(newMux(hub))
	defer srv.Close()

	_, hostBr := dialTestWS(t, srv.URL+"/host?host_id=mac1", hostHdr)
	readTestServerFrame(t, hostBr) // host_registered

	_, clientBr := dialTestWS(t, srv.URL+"/client?host_id=mac1", clientHdr)
	_, openFrame := readTestServerFrame(t, hostBr)
	var openMsg map[string]any
	_ = json.Unmarshal(openFrame[9:], &openMsg)
	sid := uint32(openMsg["sessionId"].(float64))
	readTestServerFrame(t, clientBr) // welcome

	// Idle unauthenticated leg must be closed automatically after unauthTimeout.
	_, closeFrame := readTestServerFrame(t, hostBr)
	var closeMsg map[string]any
	if err := json.Unmarshal(closeFrame[9:], &closeMsg); err != nil || closeMsg["type"] != "close_session" || uint32(closeMsg["sessionId"].(float64)) != sid {
		t.Fatalf("expected automatic close_session after unauthTimeout, got %s", closeFrame[9:])
	}
}

func TestRelayUnpairedColdStartHotReloadAndHostOnlineBroadcast(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "function-config.json")
	writePolicyFile(t, cfgPath, nil)

	hub := newDynamicRelayHub(cfgPath, "", "web000000001")
	srv := httptest.NewServer(newMux(hub))
	defer srv.Close()

	// 1. Unpaired /health & /healthz return paired=false
	for _, ep := range []string{"/health", "/healthz"} {
		resp, err := http.Get(srv.URL + ep)
		if err != nil {
			t.Fatalf("GET %s: %v", ep, err)
		}
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || body["ok"] != true || body["paired"] != false {
			t.Fatalf("unexpected %s response: status=%d body=%+v", ep, resp.StatusCode, body)
		}
	}

	// 2. /status and /info enforce IsAppOwner() strictly
	reqNonOwner, _ := http.NewRequest(http.MethodGet, srv.URL+"/info", nil)
	reqNonOwner.Header.Set("Tiana-Caller-User-Id", "usr-other")
	reqNonOwner.Header.Set("Tiana-Caller-Tenant-Id", "ten-owner")
	reqNonOwner.Header.Set("Tiana-Caller-App-Owner-Id", "usr-owner")
	reqNonOwner.Header.Set("Tiana-Caller-Web-Id", "web000000001")
	resNonOwner, _ := http.DefaultClient.Do(reqNonOwner)
	_ = resNonOwner.Body.Close()
	if resNonOwner.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for non-owner on /info, got %d", resNonOwner.StatusCode)
	}

	reqOwner, _ := http.NewRequest(http.MethodGet, srv.URL+"/status", nil)
	reqOwner.Header.Set("Tiana-Caller-User-Id", "usr-owner")
	reqOwner.Header.Set("Tiana-Caller-Tenant-Id", "ten-owner")
	reqOwner.Header.Set("Tiana-Caller-App-Owner-Id", "usr-owner")
	reqOwner.Header.Set("Tiana-Caller-Web-Id", "web000000001")
	resOwner, err := http.DefaultClient.Do(reqOwner)
	if err != nil {
		t.Fatalf("GET /status: %v", err)
	}
	var statusBody map[string]any
	_ = json.NewDecoder(resOwner.Body).Decode(&statusBody)
	_ = resOwner.Body.Close()
	if resOwner.StatusCode != 200 || statusBody["paired"] != false || statusBody["hostConnected"] != false {
		t.Fatalf("unexpected owner /status: %d %+v", resOwner.StatusCode, statusBody)
	}

	// 3. Unpaired /ws/host returns 403 Forbidden and plain HTTP /ws/client returns 409 Conflict
	resHost, _ := http.Get(srv.URL + "/ws/host?host_id=mac1")
	_ = resHost.Body.Close()
	if resHost.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for unpaired /ws/host, got %d", resHost.StatusCode)
	}
	reqPlainClient, _ := http.NewRequest(http.MethodGet, srv.URL+"/ws/client", nil)
	reqPlainClient.Header.Set("Origin", "https://example.test")
	reqPlainClient.Header.Set("Tiana-Caller-User-Id", "usr-owner")
	reqPlainClient.Header.Set("Tiana-Caller-Tenant-Id", "ten-owner")
	reqPlainClient.Header.Set("Tiana-Caller-App-Owner-Id", "usr-owner")
	reqPlainClient.Header.Set("Tiana-Caller-Web-Id", "web000000001")
	resPlainClient, _ := http.DefaultClient.Do(reqPlainClient)
	_ = resPlainClient.Body.Close()
	if resPlainClient.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 for non-WS unpaired /ws/client, got %d", resPlainClient.StatusCode)
	}

	// 4. Owner WebSocket connects in unpaired state, gets welcome(paired=false), and stays connected
	clientHdr := http.Header{}
	clientHdr.Set("Origin", "https://example.test")
	clientHdr.Set("Tiana-Caller-User-Id", "usr-owner")
	clientHdr.Set("Tiana-Caller-Tenant-Id", "ten-owner")
	clientHdr.Set("Tiana-Caller-App-Owner-Id", "usr-owner")
	clientHdr.Set("Tiana-Caller-Web-Id", "web000000001")
	_, clientBr := dialTestWS(t, srv.URL+"/client", clientHdr)
	_, welcomeFrame := readTestServerFrame(t, clientBr)
	var welcome map[string]any
	if err := json.Unmarshal(welcomeFrame[5:], &welcome); err != nil {
		t.Fatalf("decode unpaired welcome: %v", err)
	}
	if welcome["paired"] != false || welcome["webId"] != "web000000001" {
		t.Fatalf("unexpected unpaired welcome: %+v", welcome)
	}

	// 5. Hot-update FUNCTION_CONFIG_FILE with DSH_REMOTE_POLICY (zero recompile!)
	regKey := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	digest := sha256.Sum256([]byte(regKey))
	time.Sleep(15 * time.Millisecond)
	writePolicyFile(t, cfgPath, relayAccess{
		Version:       1,
		HostID:        "mac-hot",
		HostName:      "Mac Hot",
		HostDigest:    hex.EncodeToString(digest[:]),
		OwnerUserID:   "usr-owner",
		OwnerTenantID: "ten-owner",
		WebID:         "web000000001",
		Origin:        "https://example.test",
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
	})

	// 6. Host connects -> waiting Owner client immediately receives host_online broadcast!
	hostHdr := http.Header{}
	hostHdr.Set("Dsh-Host-Registration", regKey)
	_, hostBr := dialTestWS(t, srv.URL+"/ws/host?host_id=mac-hot&name=Mac+Hot", hostHdr)
	readTestServerFrame(t, hostBr) // host_registered

	_, onlineFrame := readTestServerFrame(t, clientBr)
	var onlineMsg map[string]any
	if err := json.Unmarshal(onlineFrame[5:], &onlineMsg); err != nil {
		t.Fatalf("decode host_online: %v", err)
	}
	if onlineMsg["type"] != "host_online" || onlineMsg["hostConnected"] != true || onlineMsg["hostId"] != "mac-hot" {
		t.Fatalf("expected host_online broadcast, got %+v", onlineMsg)
	}

	// 7. /info now reports paired=true, hostConnected=true
	resOwner2, _ := http.DefaultClient.Do(reqOwner)
	var statusBody2 map[string]any
	_ = json.NewDecoder(resOwner2.Body).Decode(&statusBody2)
	_ = resOwner2.Body.Close()
	if resOwner2.StatusCode != 200 || statusBody2["paired"] != true || statusBody2["hostConnected"] != true {
		t.Fatalf("expected paired & connected /info, got %d %+v", resOwner2.StatusCode, statusBody2)
	}

	// 8. Rebinding policy to a different host evicts the old host connection
	regKey2 := base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210fedcba9876543210"))
	digest2 := sha256.Sum256([]byte(regKey2))
	time.Sleep(15 * time.Millisecond)
	writePolicyFile(t, cfgPath, relayAccess{
		Version:       1,
		HostID:        "mac-new",
		HostName:      "Mac New",
		HostDigest:    hex.EncodeToString(digest2[:]),
		OwnerUserID:   "usr-owner",
		OwnerTenantID: "ten-owner",
		WebID:         "web000000001",
		Origin:        "https://example.test",
	})
	respHealth, _ := http.Get(srv.URL + "/healthz")
	_ = respHealth.Body.Close()
	if hub.isHostConnected("mac-hot") {
		t.Fatalf("expected old host mac-hot to be evicted after policy rebind")
	}
}

func TestRelayHostPublicKeySignatureAndInvalidPolicyFailClosed(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "function-config.json")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	regKey := base64.RawURLEncoding.EncodeToString([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	digest := sha256.Sum256([]byte(regKey))
	writePolicyFile(t, cfgPath, relayAccess{
		Version:       1,
		HostID:        "signed-host",
		HostDigest:    hex.EncodeToString(digest[:]),
		HostPublicKey: base64.RawURLEncoding.EncodeToString(pub),
		OwnerUserID:   "usr-owner",
		OwnerTenantID: "ten-owner",
		WebID:         "web000000002",
		Origin:        "https://example.test",
	})

	hub := newDynamicRelayHub(cfgPath, "", "web000000002")
	srv := httptest.NewServer(newMux(hub))
	defer srv.Close()

	// Missing signature must be rejected with 403
	reqBad, _ := http.NewRequest(http.MethodGet, srv.URL+"/ws/host?host_id=signed-host", nil)
	reqBad.Header.Set("Dsh-Host-Registration", regKey)
	resBad, _ := http.DefaultClient.Do(reqBad)
	_ = resBad.Body.Close()
	if resBad.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 when host signature missing, got %d", resBad.StatusCode)
	}

	// Valid signature succeeds
	ts := "1700000000"
	sig := ed25519.Sign(priv, []byte("dsh-remote-host:signed-host:"+ts))
	hostHdr := http.Header{}
	hostHdr.Set("Dsh-Host-Registration", regKey)
	hostHdr.Set("Dsh-Host-Timestamp", ts)
	hostHdr.Set("Dsh-Host-Signature", base64.RawURLEncoding.EncodeToString(sig))
	_, hostBr := dialTestWS(t, srv.URL+"/ws/host?host_id=signed-host", hostHdr)
	_, regFrame := readTestServerFrame(t, hostBr)
	if len(regFrame) < 9 {
		t.Fatalf("expected valid host_registered frame")
	}

	// Malformed policy fails closed (503) rather than falling back to unpaired
	time.Sleep(15 * time.Millisecond)
	writePolicyFile(t, cfgPath, map[string]any{"version": 99, "hostId": "BAD ID!!"})
	resFail, _ := http.Get(srv.URL + "/healthz")
	_ = resFail.Body.Close()
	if resFail.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 fail-closed on malformed policy, got %d", resFail.StatusCode)
	}
}

func TestRelayPolicyContractStrictnessTransientENOENTAndEpochReverify(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "function-config.json")

	regKey := base64.RawURLEncoding.EncodeToString([]byte("11112222333344445555666677778888"))
	digest := sha256.Sum256([]byte(regKey))
	validAccess := relayAccess{
		Version:       1,
		HostID:        "host-a",
		HostName:      "Host A",
		HostDigest:    hex.EncodeToString(digest[:]),
		OwnerUserID:   "usr-owner",
		OwnerTenantID: "ten-owner",
		WebID:         "web000000003",
		Origin:        "https://example.test",
	}

	// 1. Empty kind in DSH_REMOTE_POLICY must fail closed (requires kind == "plain")
	rawVal, _ := json.Marshal(validAccess)
	badKindCfg, _ := json.Marshal(map[string]any{
		"DSH_REMOTE_POLICY": map[string]string{
			"kind":  "",
			"value": string(rawVal),
		},
	})
	if err := os.WriteFile(cfgPath, badKindCfg, 0o600); err != nil {
		t.Fatal(err)
	}
	hub := newDynamicRelayHub(cfgPath, "", "web000000003")
	if _, _, err := hub.syncPolicy(); err == nil {
		t.Fatalf("expected error when DSH_REMOTE_POLICY kind is empty")
	}

	// 2. HostPublicKey without HostDigest must be rejected (HostDigest is mandatory)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	noDigest := validAccess
	noDigest.HostDigest = ""
	noDigest.HostPublicKey = base64.RawURLEncoding.EncodeToString(pub)
	if err := validatePairedAccess(noDigest, true, "web000000003"); err == nil {
		t.Fatalf("expected validatePairedAccess to reject missing hostDigest even with hostPublicKey")
	}

	// 3. Valid policy followed by transient ENOENT preserves lastGood paired policy
	time.Sleep(15 * time.Millisecond)
	writePolicyFile(t, cfgPath, validAccess)
	pol1, epoch1, err := hub.syncPolicy()
	if err != nil || !pol1.Paired || pol1.Access.HostID != "host-a" {
		t.Fatalf("expected valid paired policy, got pol=%+v err=%v", pol1, err)
	}
	if err := os.Remove(cfgPath); err != nil {
		t.Fatal(err)
	}
	polEnoent, epochEnoent, err := hub.syncPolicy()
	if err != nil || !polEnoent.Paired || polEnoent.Access.HostID != "host-a" || epochEnoent != epoch1 {
		t.Fatalf("expected transient ENOENT to preserve lastGood paired policy, got pol=%+v epoch=%d err=%v", polEnoent, epochEnoent, err)
	}

	// 4. Rebind advances epoch and stale-epoch registerHost / registerClient / bindSession are rejected
	regKey2 := base64.RawURLEncoding.EncodeToString([]byte("99998888777766665555444433332222"))
	digest2 := sha256.Sum256([]byte(regKey2))
	rebound := validAccess
	rebound.HostID = "host-b"
	rebound.HostName = "Host B"
	rebound.HostDigest = hex.EncodeToString(digest2[:])
	time.Sleep(15 * time.Millisecond)
	writePolicyFile(t, cfgPath, rebound)
	pol2, epoch2, err := hub.syncPolicy()
	if err != nil || !pol2.Paired || pol2.Access.HostID != "host-b" || epoch2 <= epoch1 {
		t.Fatalf("expected rebound policy with higher epoch, got pol=%+v epoch=%d (prev %d) err=%v", pol2, epoch2, epoch1, err)
	}

	// Stale epoch registerHost must be rejected
	if entry, ok := hub.registerHost("host-a", "Host A", "ten-owner", "usr-owner", nil, epoch1, pol1.Key); ok || entry != nil {
		t.Fatalf("expected registerHost with stale epoch to fail")
	}

	// Stale epoch registerClient must be rejected
	staleSess := &clientSession{
		id:       999,
		identity: callerIdentity{UserID: "usr-owner", TenantID: "ten-owner", WebID: "web000000003"},
		origin:   "https://example.test",
	}
	if hub.registerClient(staleSess, epoch1, pol1.Key, true) {
		t.Fatalf("expected registerClient with stale epoch to fail")
	}

	// Stale epoch bindSession must be rejected
	if _, err := hub.bindSession(staleSess, "host-b", epoch1); err == nil {
		t.Fatalf("expected bindSession with stale epoch to fail")
	}

	// 5. Concurrent policy reads and rebinds under -race maintain strict epoch monotonicity
	srv := httptest.NewServer(newMux(hub))
	defer srv.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			resp, err := http.Get(srv.URL + "/healthz")
			if err == nil {
				_ = resp.Body.Close()
			}
		}
	}()
	for i := 0; i < 10; i++ {
		if i%2 == 0 {
			writePolicyFile(t, cfgPath, validAccess)
		} else {
			writePolicyFile(t, cfgPath, rebound)
		}
		_, _, _ = hub.syncPolicy()
	}
	<-done

	// 6. Explicit empty config file (no DSH_REMOTE_POLICY) transitions cleanly to unpaired
	time.Sleep(15 * time.Millisecond)
	writePolicyFile(t, cfgPath, nil)
	polUnpaired, _, err := hub.syncPolicy()
	if err != nil || polUnpaired.Paired {
		t.Fatalf("expected explicit empty config file to transition to unpaired, got pol=%+v err=%v", polUnpaired, err)
	}

	// 7. Re-pair then clear via DSH_REMOTE_POLICY = { kind: "plain", value: "" } (non-empty JSON map)
	time.Sleep(15 * time.Millisecond)
	writePolicyFile(t, cfgPath, validAccess)
	polRepaired, _, err := hub.syncPolicy()
	if err != nil || !polRepaired.Paired {
		t.Fatalf("expected re-paired policy before blank-value unbind test, got pol=%+v err=%v", polRepaired, err)
	}
	time.Sleep(15 * time.Millisecond)
	blankPolicyPayload, _ := json.Marshal(map[string]any{
		"DSH_REMOTE_POLICY": map[string]string{
			"kind":  "plain",
			"value": "",
		},
		"CUSTOM_USER_VAR": map[string]string{
			"kind":  "plain",
			"value": "keep-me",
		},
	})
	if err := os.WriteFile(cfgPath, blankPolicyPayload, 0o600); err != nil {
		t.Fatalf("write blank DSH_REMOTE_POLICY: %v", err)
	}
	polCleared, _, err := hub.syncPolicy()
	if err != nil || polCleared.Paired {
		t.Fatalf("expected blank DSH_REMOTE_POLICY value to transition cleanly to unpaired, got pol=%+v err=%v", polCleared, err)
	}
}

func TestRelayHostOnlineWebIDIsolationAndSupersededEpochSuppression(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "function-config.json")
	regKey := base64.RawURLEncoding.EncodeToString([]byte("1234567890abcdef1234567890abcdef"))
	digest := sha256.Sum256([]byte(regKey))
	accessA := relayAccess{
		Version:       1,
		HostID:        "host-web-a",
		HostName:      "Host Web A",
		HostDigest:    hex.EncodeToString(digest[:]),
		OwnerUserID:   "usr-owner",
		OwnerTenantID: "ten-owner",
		WebID:         "web00000000a",
		Origin:        "https://example.test",
	}
	writePolicyFile(t, cfgPath, accessA)

	hub := newDynamicRelayHub(cfgPath, "", "")
	polA, epochA, err := hub.syncPolicy()
	if err != nil || !polA.Paired {
		t.Fatalf("expected paired policy A, got err=%v", err)
	}

	makeFakeClient := func(id uint32, webID string) (*clientSession, net.Conn) {
		serverEnd, clientEnd := net.Pipe()
		wc := &wsConn{
			maxQueued: maxQueuedBytes,
			netConn:   serverEnd,
			sendCh:    make(chan wsFrame, 16),
			closeCh:   make(chan struct{}),
			lifetime:  time.AfterFunc(time.Minute, func() {}),
		}
		go wc.writeLoop()
		t.Cleanup(func() {
			wc.close(1000, "")
			_ = clientEnd.Close()
		})
		return &clientSession{
			id:       id,
			conn:     wc,
			identity: callerIdentity{UserID: "usr-owner", TenantID: "ten-owner", WebID: webID},
			origin:   "https://example.test",
		}, clientEnd
	}

	sessMatch, pipeMatch := makeFakeClient(101, "web00000000a")
	sessOtherWeb, pipeOtherWeb := makeFakeClient(102, "web00000000b")

	hub.mu.Lock()
	hub.allClients[sessMatch.id] = sessMatch
	hub.allClients[sessOtherWeb.id] = sessOtherWeb
	hub.mu.Unlock()

	hostServerEnd, hostClientEnd := net.Pipe()
	hostWC := &wsConn{
		maxQueued: maxHostQueuedBytes,
		netConn:   hostServerEnd,
		sendCh:    make(chan wsFrame, 16),
		closeCh:   make(chan struct{}),
		lifetime:  time.AfterFunc(time.Minute, func() {}),
	}
	go hostWC.writeLoop()
	t.Cleanup(func() {
		hostWC.close(1000, "")
		_ = hostClientEnd.Close()
	})

	// 1. Register host for web00000000a -> matching client gets host_online, other webID client gets nothing
	matchGot := make(chan []byte, 1)
	go func() {
		br := bufio.NewReader(pipeMatch)
		_, payload := readTestServerFrame(t, br)
		matchGot <- payload
	}()

	otherGot := make(chan bool, 1)
	go func() {
		_ = pipeOtherWeb.SetReadDeadline(time.Now().Add(120 * time.Millisecond))
		buf := make([]byte, 16)
		n, _ := pipeOtherWeb.Read(buf)
		otherGot <- (n > 0)
	}()

	entryA, ok := hub.registerHost("host-web-a", "Host Web A", "ten-owner", "usr-owner", hostWC, epochA, polA.Key)
	if !ok || entryA == nil {
		t.Fatalf("expected registerHost to succeed")
	}

	select {
	case payload := <-matchGot:
		var msg map[string]any
		if err := json.Unmarshal(payload[5:], &msg); err != nil || msg["type"] != "host_online" || msg["hostId"] != "host-web-a" {
			t.Fatalf("unexpected host_online payload: %s err=%v", payload[5:], err)
		}
	case <-time.After(time.Second):
		t.Fatalf("matching webID client did not receive host_online")
	}
	if <-otherGot {
		t.Fatalf("client with mismatched webID must NOT receive host_online")
	}

	// 2. Policy rebind evicts entryA and advances epoch; stale broadcastHostOnline(entryA) must emit NOTHING
	accessB := accessA
	accessB.HostID = "host-web-b"
	accessB.HostName = "Host Web B"
	time.Sleep(15 * time.Millisecond)
	writePolicyFile(t, cfgPath, accessB)
	if _, _, err := hub.syncPolicy(); err != nil {
		t.Fatalf("syncPolicy B failed: %v", err)
	}

	sessAfter, pipeAfter := makeFakeClient(103, "web00000000a")
	hub.mu.Lock()
	hub.allClients[sessAfter.id] = sessAfter
	hub.mu.Unlock()

	staleGot := make(chan bool, 1)
	go func() {
		_ = pipeAfter.SetReadDeadline(time.Now().Add(120 * time.Millisecond))
		buf := make([]byte, 16)
		n, _ := pipeAfter.Read(buf)
		staleGot <- (n > 0)
	}()

	hub.broadcastHostOnline(entryA, accessA.HostDigest)
	if <-staleGot {
		t.Fatalf("evicted/superseded host entry must NOT emit stale host_online")
	}
}

func TestRelayHostOnlineAtomicEnqueueAndConcurrentPolicyEviction(t *testing.T) {
	regKey := base64.RawURLEncoding.EncodeToString([]byte("abcdef0123456789abcdef0123456789"))
	digest := sha256.Sum256([]byte(regKey))
	accessA := relayAccess{
		Version:       1,
		HostID:        "host-atomic-a",
		HostName:      "Host Atomic A",
		HostDigest:    hex.EncodeToString(digest[:]),
		OwnerUserID:   "usr-owner",
		OwnerTenantID: "ten-owner",
		WebID:         "web00000000c",
		Origin:        "https://example.test",
	}
	accessB := accessA
	accessB.HostID = "host-atomic-b"
	accessB.HostName = "Host Atomic B"

	polA := resolvedPolicy{Paired: true, Access: accessA, Key: policyComparisonKey(true, accessA)}
	polB := resolvedPolicy{Paired: true, Access: accessB, Key: policyComparisonKey(true, accessB)}

	// 1. Synchronous enqueue under h.mu.Lock() + overflowed client close(1008) after unlock
	hub := newRelayHub(accessA)
	epochA := hub.policyEpoch

	okServer, okClient := net.Pipe()
	okWC := &wsConn{
		maxQueued: maxQueuedBytes,
		netConn:   okServer,
		sendCh:    make(chan wsFrame, 4),
		closeCh:   make(chan struct{}),
		lifetime:  time.AfterFunc(time.Minute, func() {}),
	}
	t.Cleanup(func() {
		okWC.close(1000, "")
		_ = okClient.Close()
	})

	ovServer, ovClient := net.Pipe()
	ovWC := &wsConn{
		maxQueued: maxQueuedBytes,
		netConn:   ovServer,
		sendCh:    make(chan wsFrame, 1),
		closeCh:   make(chan struct{}),
		lifetime:  time.AfterFunc(time.Minute, func() {}),
	}
	// Pre-fill overflow client's sendCh so tryEnqueueBinary returns false
	ovWC.sendCh <- wsFrame{opcode: opBinary, payload: []byte{1, 2, 3}}
	t.Cleanup(func() {
		ovWC.close(1000, "")
		_ = ovClient.Close()
	})
	ovCloseCode := make(chan uint16, 1)
	go func() {
		br := bufio.NewReader(ovClient)
		op, payload := readTestServerFrame(t, br)
		if op == opClose && len(payload) >= 2 {
			ovCloseCode <- binary.BigEndian.Uint16(payload[:2])
			return
		}
		ovCloseCode <- 0
	}()

	hostServer, hostClient := net.Pipe()
	hostWC := &wsConn{
		maxQueued: maxHostQueuedBytes,
		netConn:   hostServer,
		sendCh:    make(chan wsFrame, 4),
		closeCh:   make(chan struct{}),
		lifetime:  time.AfterFunc(time.Minute, func() {}),
	}
	t.Cleanup(func() {
		hostWC.close(1000, "")
		_ = hostClient.Close()
	})

	hub.mu.Lock()
	hub.allClients[201] = &clientSession{
		id:       201,
		conn:     okWC,
		identity: callerIdentity{UserID: "usr-owner", TenantID: "ten-owner", WebID: "web00000000c"},
		origin:   "https://example.test",
	}
	hub.allClients[202] = &clientSession{
		id:       202,
		conn:     ovWC,
		identity: callerIdentity{UserID: "usr-owner", TenantID: "ten-owner", WebID: "web00000000c"},
		origin:   "https://example.test",
	}
	hub.mu.Unlock()

	if entry, ok := hub.registerHost("host-atomic-a", "Host Atomic A", "ten-owner", "usr-owner", hostWC, epochA, polA.Key); !ok || entry == nil {
		t.Fatalf("expected registerHost to succeed")
	}

	// Immediately after registerHost returns (with no writeLoop running), host_online MUST already be in sendCh
	select {
	case frame := <-okWC.sendCh:
		var msg map[string]any
		if err := json.Unmarshal(frame.payload[5:], &msg); err != nil || msg["type"] != "host_online" || msg["hostId"] != "host-atomic-a" {
			t.Fatalf("unexpected enqueued frame: %s err=%v", frame.payload[5:], err)
		}
	default:
		t.Fatalf("expected host_online to be atomically enqueued before registerHost returned")
	}

	select {
	case code := <-ovCloseCode:
		if code != 1008 {
			t.Fatalf("expected overflowed client close code 1008, got %d", code)
		}
	case <-time.After(time.Second):
		t.Fatalf("overflowed client was not closed with 1008")
	}

	// 2. Concurrent registerHost vs applyPolicy eviction under -race:
	// host_online is enqueued iff registerHost won h.mu.Lock() before applyPolicy bumped epoch.
	for i := 0; i < 40; i++ {
		h := newRelayHub(accessA)
		ep := h.policyEpoch

		cSrv, cCli := net.Pipe()
		cWC := &wsConn{
			maxQueued: maxQueuedBytes,
			netConn:   cSrv,
			sendCh:    make(chan wsFrame, 4),
			closeCh:   make(chan struct{}),
			lifetime:  time.AfterFunc(time.Minute, func() {}),
		}
		hSrv, hCli := net.Pipe()
		hWC := &wsConn{
			maxQueued: maxHostQueuedBytes,
			netConn:   hSrv,
			sendCh:    make(chan wsFrame, 4),
			closeCh:   make(chan struct{}),
			lifetime:  time.AfterFunc(time.Minute, func() {}),
		}
		h.mu.Lock()
		h.allClients[301] = &clientSession{
			id:       301,
			conn:     cWC,
			identity: callerIdentity{UserID: "usr-owner", TenantID: "ten-owner", WebID: "web00000000c"},
			origin:   "https://example.test",
		}
		h.mu.Unlock()

		// Drain close frames from peer pipes so c.close(1012, ...) never blocks
		go func() { _, _ = io.Copy(io.Discard, cCli) }()
		go func() { _, _ = io.Copy(io.Discard, hCli) }()

		start := make(chan struct{})
		regDone := make(chan bool, 1)
		polDone := make(chan struct{}, 1)
		go func() {
			<-start
			_, ok := h.registerHost("host-atomic-a", "Host Atomic A", "ten-owner", "usr-owner", hWC, ep, polA.Key)
			regDone <- ok
		}()
		go func() {
			<-start
			h.applyPolicy(polB)
			polDone <- struct{}{}
		}()
		close(start)

		regOK := <-regDone
		<-polDone
		queued := len(cWC.sendCh)
		if !regOK && queued != 0 {
			t.Fatalf("iter %d: rejected registerHost must enqueue 0 host_online frames, got %d", i, queued)
		}
		if regOK && queued != 1 {
			t.Fatalf("iter %d: accepted registerHost must atomically enqueue 1 host_online frame before eviction, got %d", i, queued)
		}
		cWC.close(1000, "")
		hWC.close(1000, "")
		_ = cCli.Close()
		_ = hCli.Close()
	}
}

func dialTestWSRawResponse(t *testing.T, rawURL string, headers http.Header) (*http.Response, net.Conn, *bufio.Reader) {
	t.Helper()
	addr := strings.TrimPrefix(rawURL, "http://")
	idx := strings.Index(addr, "/")
	hostPort := addr[:idx]
	path := addr[idx:]

	conn, err := net.DialTimeout("tcp", hostPort, 3*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", hostPort, err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var keyBytes [16]byte
	_, _ = rand.Read(keyBytes[:])
	key := base64.StdEncoding.EncodeToString(keyBytes[:])

	var req strings.Builder
	req.WriteString("GET " + path + " HTTP/1.1\r\n")
	req.WriteString("Host: " + hostPort + "\r\n")
	req.WriteString("Connection: Upgrade\r\n")
	req.WriteString("Upgrade: websocket\r\n")
	req.WriteString("Sec-WebSocket-Version: 13\r\n")
	req.WriteString("Sec-WebSocket-Key: " + key + "\r\n")
	for k, vals := range headers {
		for _, v := range vals {
			req.WriteString(k + ": " + v + "\r\n")
		}
	}
	req.WriteString("\r\n")
	if _, err := io.WriteString(conn, req.String()); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	return resp, conn, br
}

func TestRelayHostStrictMutexSameInstanceReconnectAndDifferentInstanceRejection(t *testing.T) {
	hub, hostHdr, clientHdr := fixtureRelay("mac-mutex")
	srv := httptest.NewServer(newMux(hub))
	defer srv.Close()

	// 1. Invalid instance_id is rejected with 400
	respBad, _, _ := dialTestWSRawResponse(t, srv.URL+"/ws/host?host_id=mac-mutex&instance_id=bad!id", hostHdr)
	_ = respBad.Body.Close()
	if respBad.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid instance_id, got %d", respBad.StatusCode)
	}

	// 2. Host A connects with instance_id=inst-A
	hostAConn, hostABr := dialTestWS(t, srv.URL+"/ws/host?host_id=mac-mutex&name=HostA&instance_id=inst-A", hostHdr)
	_, regA := readTestServerFrame(t, hostABr)
	var regAMsg map[string]any
	if err := json.Unmarshal(regA[9:], &regAMsg); err != nil || regAMsg["type"] != "host_registered" {
		t.Fatalf("unexpected host A reg: %s %v", regA[9:], err)
	}

	// 3. Host B with DIFFERENT instance_id=inst-B is rejected with 409 Conflict before upgrade; Host A remains alive!
	respB, _, _ := dialTestWSRawResponse(t, srv.URL+"/ws/host?host_id=mac-mutex&name=HostB&instance_id=inst-B", hostHdr)
	var bodyB map[string]any
	_ = json.NewDecoder(respB.Body).Decode(&bodyB)
	_ = respB.Body.Close()
	if respB.StatusCode != http.StatusConflict || bodyB["error"] != "host_already_connected" || bodyB["hostId"] != "mac-mutex" {
		t.Fatalf("expected 409 host_already_connected for different instance_id, got %d %+v", respB.StatusCode, bodyB)
	}

	// Verify Host A is still connected and actively forwarding traffic
	clientConn, clientBr := dialTestWS(t, srv.URL+"/ws/client?host_id=mac-mutex", clientHdr)
	_, openFrame := readTestServerFrame(t, hostABr)
	var openMsg map[string]any
	if err := json.Unmarshal(openFrame[9:], &openMsg); err != nil || openMsg["type"] != "open_session" {
		t.Fatalf("expected Host A to remain alive and receive open_session, got %s %v", openFrame[9:], err)
	}
	readTestServerFrame(t, clientBr) // welcome
	_ = clientConn.Close()
	readTestServerFrame(t, hostABr) // close_session

	// 4. Race-window conflict directly in registerHostWithInstance returns hostRegConflict and keeps Host A intact
	raceSrv, raceCli := net.Pipe()
	raceWC := &wsConn{
		maxQueued: maxHostQueuedBytes,
		netConn:   raceSrv,
		sendCh:    make(chan wsFrame, 4),
		closeCh:   make(chan struct{}),
		lifetime:  time.AfterFunc(time.Minute, func() {}),
	}
	defer func() {
		raceWC.close(1000, "")
		_ = raceCli.Close()
	}()
	pol, epoch, err := hub.syncPolicy()
	if err != nil {
		t.Fatalf("syncPolicy: %v", err)
	}
	if entry, status := hub.registerHostWithInstance("mac-mutex", "HostB", "ten-owner", "usr-owner", "inst-B", raceWC, epoch, pol.Key); status != hostRegConflict || entry != nil {
		t.Fatalf("expected hostRegConflict in race window, got status=%v entry=%v", status, entry)
	}
	if !hub.isHostConnected("mac-mutex") {
		t.Fatalf("Host A must remain connected after race-window rejection")
	}

	// 5. Same instance_id=inst-A reconnects -> smoothly replaces previous Host A connection
	hostAClosed := make(chan uint16, 1)
	go func() {
		op, payload := readTestServerFrame(t, hostABr)
		if op == opClose && len(payload) >= 2 {
			hostAClosed <- binary.BigEndian.Uint16(payload[:2])
			return
		}
		hostAClosed <- 0
	}()

	hostA2Conn, hostA2Br := dialTestWS(t, srv.URL+"/ws/host?host_id=mac-mutex&name=HostA-Reconn&instance_id=inst-A", hostHdr)
	defer func() { _ = hostA2Conn.Close() }()
	_, regA2 := readTestServerFrame(t, hostA2Br)
	var regA2Msg map[string]any
	if err := json.Unmarshal(regA2[9:], &regA2Msg); err != nil || regA2Msg["type"] != "host_registered" || regA2Msg["name"] != "HostA-Reconn" {
		t.Fatalf("expected same-instance reconnect to succeed, got %s %v", regA2[9:], err)
	}
	select {
	case code := <-hostAClosed:
		if code != 1000 {
			t.Fatalf("expected previous same-instance connection to close with 1000, got %d", code)
		}
	case <-time.After(time.Second):
		t.Fatalf("previous same-instance connection was not closed on smooth replacement")
	}
	_ = hostAConn.Close()
}

func TestRelayHostStrictMutexLegacyBidirectionalCompatibility(t *testing.T) {
	hub, hostHdr, _ := fixtureRelay("mac-legacy")
	srv := httptest.NewServer(newMux(hub))
	defer srv.Close()

	// Case 1: Legacy host (no instance_id) connects first -> new host (with instance_id) AND second legacy host are both rejected with 409
	legacy1Conn, legacy1Br := dialTestWS(t, srv.URL+"/ws/host?host_id=mac-legacy&name=Legacy1", hostHdr)
	readTestServerFrame(t, legacy1Br) // host_registered

	respNew, _, _ := dialTestWSRawResponse(t, srv.URL+"/ws/host?host_id=mac-legacy&name=New1&instance_id=inst-new-1", hostHdr)
	_ = respNew.Body.Close()
	if respNew.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 when new host tries to kick online legacy host, got %d", respNew.StatusCode)
	}

	respLegacy2, _, _ := dialTestWSRawResponse(t, srv.URL+"/ws/host?host_id=mac-legacy&name=Legacy2", hostHdr)
	_ = respLegacy2.Body.Close()
	if respLegacy2.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 when second legacy host tries to kick online legacy host, got %d", respLegacy2.StatusCode)
	}

	if !hub.isHostConnected("mac-legacy") {
		t.Fatalf("legacy host 1 must stay connected")
	}
	_ = legacy1Conn.Close()

	// Wait for legacy1 unregister
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && hub.isHostConnected("mac-legacy") {
		time.Sleep(10 * time.Millisecond)
	}
	if hub.isHostConnected("mac-legacy") {
		t.Fatalf("expected legacy host 1 to unregister after close")
	}

	// Case 2: New host (with instance_id) connects -> legacy host (no instance_id) is rejected with 409 and new host stays alive
	newConn, newBr := dialTestWS(t, srv.URL+"/ws/host?host_id=mac-legacy&name=New1&instance_id=inst-new-1", hostHdr)
	defer func() { _ = newConn.Close() }()
	readTestServerFrame(t, newBr) // host_registered

	respLegacyAfter, _, _ := dialTestWSRawResponse(t, srv.URL+"/ws/host?host_id=mac-legacy&name=LegacyLate", hostHdr)
	_ = respLegacyAfter.Body.Close()
	if respLegacyAfter.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 when legacy host tries to kick online new host, got %d", respLegacyAfter.StatusCode)
	}
	if !hub.isHostConnected("mac-legacy") {
		t.Fatalf("new host must stay connected after legacy rejection")
	}
}

func TestRelayHostStatusProbeAuthAndVisibility(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "function-config.json")
	writePolicyFile(t, cfgPath, nil)

	hub := newDynamicRelayHub(cfgPath, "", "web000000010")
	srv := httptest.NewServer(newMux(hub))
	defer srv.Close()

	// 1. Unpaired: direct unauthenticated request -> 403
	resUnauth, _ := http.Get(srv.URL + "/host-status")
	_ = resUnauth.Body.Close()
	if resUnauth.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for unauthenticated /host-status when unpaired, got %d", resUnauth.StatusCode)
	}

	// 2. Unpaired: authenticated Web App Owner -> 200 paired=false hostConnected=false
	reqOwner, _ := http.NewRequest(http.MethodGet, srv.URL+"/host-status", nil)
	reqOwner.Header.Set("Tiana-Caller-User-Id", "usr-owner")
	reqOwner.Header.Set("Tiana-Caller-Tenant-Id", "ten-owner")
	reqOwner.Header.Set("Tiana-Caller-App-Owner-Id", "usr-owner")
	reqOwner.Header.Set("Tiana-Caller-Web-Id", "web000000010")
	resOwnerUnpaired, err := http.DefaultClient.Do(reqOwner)
	if err != nil {
		t.Fatalf("owner /host-status: %v", err)
	}
	var bodyOwnerUnpaired map[string]any
	_ = json.NewDecoder(resOwnerUnpaired.Body).Decode(&bodyOwnerUnpaired)
	_ = resOwnerUnpaired.Body.Close()
	if resOwnerUnpaired.StatusCode != 200 || bodyOwnerUnpaired["paired"] != false || bodyOwnerUnpaired["hostConnected"] != false {
		t.Fatalf("unexpected unpaired owner /host-status: %d %+v", resOwnerUnpaired.StatusCode, bodyOwnerUnpaired)
	}

	// 3. Pair Relay with policy
	regKey := base64.RawURLEncoding.EncodeToString([]byte("aaaa1111bbbb2222cccc3333dddd4444"))
	digest := sha256.Sum256([]byte(regKey))
	digestHex := hex.EncodeToString(digest[:])
	updatedAt := "2026-11-22T03:00:00Z"
	time.Sleep(15 * time.Millisecond)
	writePolicyFile(t, cfgPath, relayAccess{
		Version:       1,
		HostID:        "probe-host",
		HostName:      "Probe Host",
		HostDigest:    digestHex,
		OwnerUserID:   "usr-owner",
		OwnerTenantID: "ten-owner",
		WebID:         "web000000010",
		Origin:        "https://example.test",
		UpdatedAt:     updatedAt,
	})

	// Unauthorized cases when paired MUST all return 403
	badRequests := []struct {
		name    string
		path    string
		headers map[string]string
	}{
		{"no headers", "/host-status", nil},
		{"wrong registration key", "/host-status", map[string]string{"Dsh-Host-Registration": base64.RawURLEncoding.EncodeToString([]byte("zzzz9999yyyy8888xxxx7777wwww6666"))}},
		{"wrong policy digest", "/host-status", map[string]string{"Dsh-Host-Policy-Digest": strings.Repeat("0", 64)}},
		{"policy digest with Origin header", "/host-status", map[string]string{"Dsh-Host-Policy-Digest": digestHex, "Origin": "https://example.test"}},
		{"policy digest with mismatched host_id", "/host-status?host_id=other-host", map[string]string{"Dsh-Host-Policy-Digest": digestHex}},
		{"policy digest with mismatched web_id", "/host-status", map[string]string{"Dsh-Host-Policy-Digest": digestHex, "Dsh-Host-Web-Id": "web999999999"}},
		{"non-owner caller headers", "/host-status", map[string]string{
			"Tiana-Caller-User-Id":      "usr-intruder",
			"Tiana-Caller-Tenant-Id":    "ten-owner",
			"Tiana-Caller-App-Owner-Id": "usr-owner",
			"Tiana-Caller-Web-Id":       "web000000010",
		}},
		{"policy digest combined with non-owner caller header", "/host-status", map[string]string{
			"Dsh-Host-Policy-Digest":    digestHex,
			"Tiana-Caller-User-Id":      "usr-intruder",
			"Tiana-Caller-Tenant-Id":    "ten-owner",
			"Tiana-Caller-App-Owner-Id": "usr-owner",
			"Tiana-Caller-Web-Id":       "web000000010",
		}},
	}
	for _, tc := range badRequests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, srv.URL+tc.path, nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("do request: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("expected 403 for %s, got %d", tc.name, resp.StatusCode)
			}
		})
	}

	// Authorized via Dsh-Host-Policy-Digest while host offline -> hostConnected=false
	reqDigest, _ := http.NewRequest(http.MethodGet, srv.URL+"/host-status?host_id=probe-host", nil)
	reqDigest.Header.Set("Dsh-Host-Policy-Digest", digestHex)
	reqDigest.Header.Set("Dsh-Host-Web-Id", "web000000010")
	resOffline, err := http.DefaultClient.Do(reqDigest)
	if err != nil {
		t.Fatalf("digest offline probe: %v", err)
	}
	var bodyOffline map[string]any
	_ = json.NewDecoder(resOffline.Body).Decode(&bodyOffline)
	_ = resOffline.Body.Close()
	if resOffline.StatusCode != 200 || bodyOffline["paired"] != true || bodyOffline["hostConnected"] != false ||
		bodyOffline["hostId"] != "probe-host" || bodyOffline["hostName"] != "Probe Host" || bodyOffline["updatedAt"] != updatedAt {
		t.Fatalf("unexpected offline /host-status: %d %+v", resOffline.StatusCode, bodyOffline)
	}

	// Connect host -> both Dsh-Host-Policy-Digest and Dsh-Host-Registration and Owner see hostConnected=true
	hostHdr := http.Header{}
	hostHdr.Set("Dsh-Host-Registration", regKey)
	hostConn, hostBr := dialTestWS(t, srv.URL+"/ws/host?host_id=probe-host&name=Probe+Live&instance_id=inst-probe-1", hostHdr)
	readTestServerFrame(t, hostBr) // host_registered

	for _, probe := range []struct {
		name string
		hdr  http.Header
	}{
		{"policy-digest", http.Header{"Dsh-Host-Policy-Digest": {digestHex}, "Dsh-Host-Web-Id": {"web000000010"}}},
		{"host-registration", hostHdr},
		{"app-owner", reqOwner.Header},
	} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/host-status", nil)
		req.Header = probe.hdr.Clone()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s /host-status: %v", probe.name, err)
		}
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || body["paired"] != true || body["hostConnected"] != true ||
			body["hostId"] != "probe-host" || body["hostName"] != "Probe Live" || body["updatedAt"] != updatedAt {
			t.Fatalf("unexpected online /host-status (%s): %d %+v", probe.name, resp.StatusCode, body)
		}
	}

	_ = hostConn.Close()
}
