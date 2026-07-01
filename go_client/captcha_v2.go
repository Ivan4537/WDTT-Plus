package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	mathrand "math/rand"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	neturl "net/url"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
)

const (
	captchaV2APIVersion    = "5.131"
	captchaV2ScriptVersion = "1.1.1367"
	captchaV2DeviceInfo    = `{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1080,"innerWidth":1920,"innerHeight":951,"devicePixelRatio":1,"language":"en-US","languages":["en-US","en"],"webdriver":false,"hardwareConcurrency":8,"notificationsPermission":"denied"}`
)

var (
	reCaptchaV2PowInput   = regexp.MustCompile(`const\s+powInput\s*=\s*"([^"]+)"`)
	reCaptchaV2Difficulty = regexp.MustCompile(`const\s+difficulty\s*=\s*(\d+)`)
	reCaptchaV2WindowInit = regexp.MustCompile(`(?s)window\.init\s*=`)
	reCaptchaV2ScriptSrc  = regexp.MustCompile(`(?is)<script[^>]+\bsrc\s*=\s*["']([^"']*not_robot_captcha[^"']*)["']`)
	reCaptchaV2DebugInfo  = regexp.MustCompile(`(?i)debug_?info\s*:\s*(?:[^"',{};]+?\|\|\s*)?["']([a-f0-9]{64})["']`)
	reCaptchaV2Version    = regexp.MustCompile(`(?:^|/)vkid/([0-9.]+)/not_robot_captcha\.js(?:$|[?#])`)

	errCaptchaV2RateLimit = errors.New("captcha session rate limit reached")
	errCaptchaV2Bot       = errors.New("captcha bot challenge")

	captchaV2MaxAttempts = 2

	captchaV2DebugCache  sync.Map // scriptURL -> string
	captchaV2HeaderOrder = []string{
		"host",
		"content-length",
		"sec-ch-ua-platform",
		"accept-language",
		"sec-ch-ua",
		"content-type",
		"sec-ch-ua-mobile",
		"user-agent",
		"accept",
		"origin",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-dest",
		"referer",
		"accept-encoding",
		"priority",
	}
	captchaV2PHeaderOrder = []string{":method", ":path", ":authority", ":scheme"}
)

type captchaV2Init struct {
	Data captchaV2InitData `json:"data"`
}

type captchaV2InitData struct {
	ShowCaptchaType string                 `json:"show_captcha_type"`
	CaptchaSettings []captchaV2InitSetting `json:"captcha_settings"`
}

type captchaV2InitSetting struct {
	Type     string `json:"type"`
	Settings string `json:"settings"`
}

type captchaV2Page struct {
	PowInput      string
	PowDifficulty int
	ScriptURL     string
	ScriptVersion string
	Domain        string
	IDOrigin      string
	Init          *captchaV2Init
}

type captchaV2Check struct {
	Status       string
	SuccessToken string
	ShowType     string
}

type captchaV2Settings struct {
	ShowType string
	ByType   map[string]string
}

type captchaV2ShowTypeError struct {
	ShowType string
}

func (e *captchaV2ShowTypeError) Error() string {
	return "captcha show type mismatch: " + e.ShowType
}

type captchaV2Session struct {
	ctx           context.Context
	client        tlsclient.HttpClient
	profile       Profile
	savedProfile  *SavedProfile
	componentDone bool
}

func solveVkCaptchaV2(
	ctx context.Context,
	captchaErr *VkCaptchaError,
	client tlsclient.HttpClient,
	profile Profile,
	savedProfile *SavedProfile,
) (string, error) {
	return solveVkCaptchaV2Attempts(ctx, captchaErr, client, profile, savedProfile, captchaV2MaxAttempts)
}

func solveVkCaptchaV2Attempts(
	ctx context.Context,
	captchaErr *VkCaptchaError,
	client tlsclient.HttpClient,
	profile Profile,
	savedProfile *SavedProfile,
	maxAttempts int,
) (string, error) {
	if captchaErr == nil || captchaErr.SessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri")
	}
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	log.Printf("[КАПЧА] Решаю VK Smart Captcha автоматически (v2, попыток=%d)...", maxAttempts)

	s := &captchaV2Session{ctx: ctx, client: client, profile: profile, savedProfile: savedProfile}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		token, solveErr := s.solveOnce(captchaErr)
		if solveErr == nil {
			return token, nil
		}
		log.Printf("[КАПЧА] v2 попытка %d не прошла, fallback продолжит: %v", attempt, solveErr)
		if errors.Is(solveErr, errCaptchaV2RateLimit) {
			return "", solveErr
		}

		backoffSteps := attempt
		if backoffSteps > 10 {
			backoffSteps = 10
		}
		timer := time.NewTimer(time.Duration(backoffSteps) * 500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
	return "", fmt.Errorf("v2 captcha attempts exhausted (%d)", maxAttempts)
}

func (s *captchaV2Session) solveOnce(captchaErr *VkCaptchaError) (string, error) {
	html, err := s.fetchCaptchaHTML(captchaErr.RedirectURI)
	if err != nil {
		return "", err
	}

	page, err := parseCaptchaV2Page(html)
	if err != nil {
		return "", err
	}
	page.Domain = inferCaptchaV2Domain(captchaErr.RedirectURI, page.ScriptURL)
	page.IDOrigin = captchaV2IDOriginForDomain(page.Domain)
	if page.PowInput == "" {
		return "", errors.New("failed to find PoW settings")
	}

	sliderSettings := ""
	if page.Init != nil {
		for _, setting := range page.Init.Data.CaptchaSettings {
			if setting.Type == "slider" {
				sliderSettings = setting.Settings
			}
		}
	}
	log.Printf("[КАПЧА] v2 solving pow difficulty=%d", page.PowDifficulty)
	hash, nonce := solveCaptchaPoWV2(s.ctx, page.PowInput, page.PowDifficulty)
	if hash == "" {
		return "", errors.New("captcha pow failed")
	}
	hash = encodeCaptchaPoWV2(hash, nonce)
	log.Printf("[КАПЧА] v2 pow solved")

	adFP, err := captchaV2SessionAdFP(captchaErr.AdFP)
	if err != nil {
		return "", err
	}
	settingsBase := captchaV2BaseValuesForChallenge(captchaErr.SessionToken, page.Domain, "")
	if _, initErr := s.captchaRequest("captchaNotRobot.initSession", settingsBase); initErr != nil {
		return "", fmt.Errorf("captcha initSession failed: %w", initErr)
	}
	settingsRaw, settingsErr := s.captchaRequest("captchaNotRobot.settings", settingsBase)
	if settingsErr != nil {
		return "", fmt.Errorf("captcha settings failed: %w", settingsErr)
	}
	apiSettings, settingsParseErr := parseCaptchaV2Settings(settingsRaw)
	if settingsParseErr != nil {
		log.Printf("[КАПЧА] v2 settings response parse warning: %v", settingsParseErr)
	} else {
		if actual := apiSettings.ByType["slider"]; actual != "" {
			sliderSettings = actual
		}
		log.Printf("[КАПЧА] v2 settings show_type=%s available=%s", captchaV2ActualVersionForLog(apiSettings.ShowType), captchaV2SettingsTypes(apiSettings.ByType))
	}

	browserFP, err := captchaV2BrowserFP()
	if err != nil {
		return "", err
	}
	if s.savedProfile != nil && strings.TrimSpace(s.savedProfile.BrowserFp) != "" {
		browserFP = s.savedProfile.BrowserFp
	}
	base := captchaV2BaseValuesForChallenge(captchaErr.SessionToken, page.Domain, adFP)

	if page.ScriptVersion != "" && page.ScriptVersion != captchaV2ScriptVersion {
		log.Printf("[КАПЧА] v2 script version drift: known=%s actual=%s url=%s", captchaV2ScriptVersion, page.ScriptVersion, page.ScriptURL)
	}
	log.Printf("[КАПЧА] v2 script actual_version=%s domain=%s", captchaV2ActualVersionForLog(page.ScriptVersion), page.Domain)

	debugInfo, err := s.fetchDebugInfo(page.ScriptURL, page.IDOrigin)
	if err != nil {
		return "", fmt.Errorf("failed to fetch debug info: %w (script_version=%s script_url=%s)", err, captchaV2ActualVersionForLog(page.ScriptVersion), page.ScriptURL)
	}

	bootstrapShowType := ""
	if page.Init != nil {
		bootstrapShowType = page.Init.Data.ShowCaptchaType
	}
	// The bootstrap may advertise slider while the live session still starts with
	// a checkbox. Let the check response promote the session to slider.
	showType := "checkbox"
	log.Printf("[КАПЧА] v2 bootstrap show_type=%s, starting with checkbox", captchaV2ActualVersionForLog(bootstrapShowType))
	var token string
	for {
		log.Printf("[КАПЧА] v2 solving show_type=%s", showType)
		switch showType {
		case "slider":
			token, err = s.solveSliderCaptcha(captchaErr.SessionToken, page.Domain, adFP, browserFP, hash, sliderSettings, debugInfo)
		case "checkbox", "":
			token, err = s.solveCheckboxCaptcha(captchaErr.SessionToken, page.Domain, adFP, browserFP, hash, debugInfo)
		default:
			return "", fmt.Errorf("unsupported captcha type: %s", showType)
		}
		if err == nil {
			break
		}
		if errors.Is(err, errCaptchaV2Bot) && !strings.EqualFold(showType, "slider") && sliderSettings != "" {
			log.Printf("[КАПЧА] v2 checkbox returned BOT, trying slider")
			showType = "slider"
			continue
		}
		var stErr *captchaV2ShowTypeError
		if errors.As(err, &stErr) && stErr.ShowType != "" {
			showType = stErr.ShowType
			continue
		}
		if !strings.EqualFold(showType, "slider") && sliderSettings != "" && !errors.Is(err, errCaptchaV2RateLimit) {
			log.Printf("[КАПЧА] v2 checkbox failed (%v), trying slider", err)
			showType = "slider"
			continue
		}
		return "", err
	}

	if _, endErr := s.captchaRequest("captchaNotRobot.endSession", base); endErr != nil {
		log.Printf("[КАПЧА] v2 endSession failed: %v", endErr)
	}
	return token, nil
}

func captchaV2BaseValues(sessionToken string) [][2]string {
	return captchaV2BaseValuesForDomain(sessionToken, "vk.ru")
}

func captchaV2BaseValuesForDomain(sessionToken string, domain string) [][2]string {
	return captchaV2BaseValuesForChallenge(sessionToken, domain, "")
}

func captchaV2BaseValuesForChallenge(sessionToken string, domain string, adFP string) [][2]string {
	if domain == "" {
		domain = "vk.ru"
	}
	return [][2]string{
		{"session_token", sessionToken},
		{"domain", domain},
		{"adFp", adFP},
		{"access_token", ""},
	}
}

func captchaV2BrowserFP() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("browser fp generate: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func captchaV2SessionAdFP(challengeAdFP string) (string, error) {
	if strings.TrimSpace(challengeAdFP) != "" {
		return strings.TrimSpace(challengeAdFP), nil
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("adFp generate: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *captchaV2Session) fetchCaptchaHTML(redirectURI string) (string, error) {
	body, err := s.doRaw(fhttp.MethodGet, redirectURI, nil, map[string]string{
		"Accept":         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Sec-Fetch-Dest": "document",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-Site": "cross-site",
	})
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (s *captchaV2Session) fetchDebugInfo(scriptURL string, idOrigin string) (string, error) {
	if cached, ok := captchaV2DebugCache.Load(scriptURL); ok {
		if cachedDebugInfo, ok := cached.(string); ok {
			return cachedDebugInfo, nil
		}
		captchaV2DebugCache.Delete(scriptURL)
	}
	if idOrigin == "" {
		idOrigin = captchaV2IDOriginForURL(scriptURL)
	}
	body, err := s.doRaw(fhttp.MethodGet, scriptURL, nil, map[string]string{
		"Accept":  "text/javascript,*/*",
		"Referer": idOrigin + "/",
	})
	if err != nil {
		return "", err
	}
	m := reCaptchaV2DebugInfo.FindSubmatch(body)
	if len(m) < 2 {
		return "", errors.New("debug_info match not found")
	}
	v := string(m[1])
	captchaV2DebugCache.Store(scriptURL, v)
	log.Printf("[КАПЧА] v2 debug_info fetched url=%s", scriptURL)
	return v, nil
}

func parseCaptchaV2Page(html string) (*captchaV2Page, error) {
	page := &captchaV2Page{}

	initJSON, err := extractCaptchaV2WindowInit(html)
	if err != nil {
		return nil, errors.New("captcha init json not found")
	}
	var init captchaV2Init
	if err := json.Unmarshal([]byte(initJSON), &init); err != nil {
		return nil, fmt.Errorf("captcha init json parse: %w", err)
	}
	page.Init = &init

	match := reCaptchaV2ScriptSrc.FindStringSubmatch(html)
	if len(match) < 2 {
		return nil, errors.New("captcha script url not found")
	}
	scriptURL, err := resolveCaptchaV2ScriptURL(match[1])
	if err != nil {
		return nil, err
	}
	page.ScriptURL = scriptURL
	page.ScriptVersion = captchaV2ScriptVersionFromURL(scriptURL)
	page.Domain = inferCaptchaV2Domain("", scriptURL)
	page.IDOrigin = captchaV2IDOriginForDomain(page.Domain)

	if m := reCaptchaV2PowInput.FindStringSubmatch(html); len(m) >= 2 {
		page.PowInput = m[1]
	}
	if page.PowInput == "" {
		return page, nil
	}

	match = reCaptchaV2Difficulty.FindStringSubmatch(html)
	if len(match) < 2 {
		return nil, errors.New("captcha difficulty const not found")
	}
	difficulty, err := strconv.Atoi(match[1])
	if err != nil || difficulty <= 0 {
		return nil, fmt.Errorf("invalid captcha difficulty %q", match[1])
	}
	page.PowDifficulty = difficulty
	return page, nil
}

func extractCaptchaV2WindowInit(html string) (string, error) {
	loc := reCaptchaV2WindowInit.FindStringIndex(html)
	if loc == nil {
		return "", errors.New("window.init assignment not found")
	}
	start := strings.IndexByte(html[loc[1]:], '{')
	if start < 0 {
		return "", errors.New("window.init object start not found")
	}
	start += loc[1]

	inString := false
	escaped := false
	var quote byte
	depth := 0
	for i := start; i < len(html); i++ {
		c := html[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				inString = false
			}
			continue
		}
		if c == '"' || c == '\'' {
			inString = true
			quote = c
			continue
		}
		if c == '{' {
			depth++
			continue
		}
		if c == '}' {
			depth--
			if depth == 0 {
				return html[start : i+1], nil
			}
		}
	}
	return "", errors.New("window.init object end not found")
}

func resolveCaptchaV2ScriptURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("captcha script url empty")
	}
	if strings.HasPrefix(raw, "//") {
		raw = "https:" + raw
	}
	u, err := neturl.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("captcha script url parse: %w", err)
	}
	if !u.IsAbs() {
		base, _ := neturl.Parse("https://id.vk.ru/")
		u = base.ResolveReference(u)
	}
	if u.Scheme != "https" || !strings.Contains(u.Hostname(), "vk.") {
		return "", fmt.Errorf("unexpected captcha script url: %s", raw)
	}
	return u.String(), nil
}

func captchaV2ScriptVersionFromURL(scriptURL string) string {
	if m := reCaptchaV2Version.FindStringSubmatch(scriptURL); len(m) > 1 {
		return m[1]
	}
	return ""
}

func captchaV2ActualVersionForLog(version string) string {
	if version == "" {
		return "unknown"
	}
	return version
}

func inferCaptchaV2Domain(redirectURI string, scriptURL string) string {
	if u, err := neturl.Parse(redirectURI); err == nil {
		if domain := normalizeCaptchaV2Domain(u.Query().Get("domain")); domain != "" {
			return domain
		}
	}
	for _, raw := range []string{redirectURI, scriptURL} {
		u, err := neturl.Parse(raw)
		if err != nil {
			continue
		}
		if domain := normalizeCaptchaV2Domain(u.Hostname()); domain != "" {
			return domain
		}
	}
	return "vk.ru"
}

func normalizeCaptchaV2Domain(raw string) string {
	host := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case host == "vk.ru" || strings.HasSuffix(host, ".vk.ru"):
		return "vk.ru"
	case host == "vk.com" || strings.HasSuffix(host, ".vk.com"):
		return "vk.com"
	default:
		return ""
	}
}

func captchaV2IDOriginForURL(raw string) string {
	return captchaV2IDOriginForDomain(inferCaptchaV2Domain("", raw))
}

func captchaV2IDOriginForDomain(domain string) string {
	if strings.EqualFold(domain, "vk.com") {
		return "https://id.vk.com"
	}
	return "https://id.vk.ru"
}

func captchaV2DomainFromForm(form [][2]string) string {
	for _, kv := range form {
		if kv[0] == "domain" {
			if domain := normalizeCaptchaV2Domain(kv[1]); domain != "" {
				return domain
			}
		}
	}
	return "vk.ru"
}

func (s *captchaV2Session) captchaRequest(method string, form [][2]string) (map[string]any, error) {
	domain := captchaV2DomainFromForm(form)
	endpoint := "https://api." + domain + "/method/" + method + "?v=" + captchaV2APIVersion
	idOrigin := captchaV2IDOriginForDomain(domain)
	body, err := s.doRaw(fhttp.MethodPost, endpoint, form, map[string]string{
		"Origin":   idOrigin,
		"Referer":  idOrigin + "/",
		"Priority": "u=1, i",
	})
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("captcha api decode: %w", err)
	}
	return out, nil
}

func (s *captchaV2Session) performCaptchaCheck(
	sessionToken string,
	domain string,
	adFP string,
	browserFP string,
	hash string,
	answerJSON string,
	cursor string,
	debugInfo string,
) (*captchaV2Check, error) {
	values := [][2]string{
		{"session_token", sessionToken},
		{"domain", domain},
		{"adFp", adFP},
		{"accelerometer", "[]"},
		{"gyroscope", "[]"},
		{"motion", "[]"},
		{"cursor", cursor},
		{"taps", "[]"},
		{"connectionRtt", captchaV2ConnectionRtt()},
		{"connectionDownlink", captchaV2ConnectionDownlink()},
		{"browser_fp", browserFP},
		{"hash", hash},
		{"answer", base64.StdEncoding.EncodeToString([]byte(answerJSON))},
		{"debug_info", debugInfo},
		{"access_token", ""},
	}
	resp, err := s.captchaRequest("captchaNotRobot.check", values)
	if err != nil {
		return nil, fmt.Errorf("captcha check failed: %w", err)
	}
	check, err := parseCaptchaV2Check(resp)
	if err != nil {
		return nil, err
	}
	if check.ShowType != "" {
		log.Printf("[КАПЧА] v2 check status=%s show_type=%s", check.Status, check.ShowType)
	} else {
		log.Printf("[КАПЧА] v2 check status=%s", check.Status)
	}
	return check, nil
}

func parseCaptchaV2Check(raw map[string]any) (*captchaV2Check, error) {
	resp, ok := raw["response"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid captcha check response: %v", raw)
	}
	out := &captchaV2Check{
		Status:       captchaV2StringifyAny(resp["status"]),
		SuccessToken: captchaV2StringifyAny(resp["success_token"]),
		ShowType:     captchaV2StringifyAny(resp["show_captcha_type"]),
	}
	if out.Status == "" {
		return nil, fmt.Errorf("captcha check status missing: %v", raw)
	}
	return out, nil
}

func captchaV2ConnectionRtt() string {
	samples := make([]int, 12)
	base := 45 + mathrand.Intn(35)
	for i := range samples {
		samples[i] = base + mathrand.Intn(18) - 6
		if mathrand.Intn(12) == 0 {
			samples[i] += 20 + mathrand.Intn(45)
		}
		if samples[i] < 20 {
			samples[i] = 20
		}
	}
	body, _ := json.Marshal(samples)
	return string(body)
}

func captchaV2ConnectionDownlink() string {
	samples := make([]float64, 12)
	base := 6.5 + mathrand.Float64()*8.5
	for i := range samples {
		value := base + mathrand.Float64()*1.4 - 0.7
		if value < 0.5 {
			value = 0.5
		}
		samples[i] = math.Round(value*10) / 10
	}
	body, _ := json.Marshal(samples)
	return string(body)
}

func parseCaptchaV2Settings(raw map[string]any) (*captchaV2Settings, error) {
	resp, ok := raw["response"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid captcha settings response: %v", raw)
	}
	out := &captchaV2Settings{
		ShowType: captchaV2StringifyAny(resp["show_captcha_type"]),
		ByType:   make(map[string]string),
	}
	items, ok := expandCaptchaV2Settings(resp["captcha_settings"])
	if !ok {
		return out, nil
	}
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		captchaType := strings.TrimSpace(captchaV2StringifyAny(entry["type"]))
		if captchaType == "" {
			continue
		}
		setting, err := normalizeCaptchaV2Setting(entry["settings"])
		if err != nil {
			return nil, fmt.Errorf("invalid captcha_settings for %s: %w", captchaType, err)
		}
		out.ByType[captchaType] = setting
	}
	return out, nil
}

func expandCaptchaV2Settings(raw any) ([]any, bool) {
	switch value := raw.(type) {
	case nil:
		return nil, false
	case []any:
		return value, true
	case map[string]any:
		items := make([]any, 0, len(value))
		for captchaType, setting := range value {
			items = append(items, map[string]any{"type": captchaType, "settings": setting})
		}
		return items, true
	case string:
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, false
		}
		var decoded any
		if json.Unmarshal([]byte(value), &decoded) == nil {
			return expandCaptchaV2Settings(decoded)
		}
	}
	return nil, false
}

func normalizeCaptchaV2Setting(raw any) (string, error) {
	switch value := raw.(type) {
	case nil:
		return "", nil
	case string:
		return value, nil
	default:
		data, err := json.Marshal(value)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
}

func captchaV2SettingsTypes(settings map[string]string) string {
	if len(settings) == 0 {
		return "none"
	}
	types := make([]string, 0, len(settings))
	for captchaType := range settings {
		types = append(types, captchaType)
	}
	sort.Strings(types)
	return strings.Join(types, ",")
}

func (s *captchaV2Session) ensureCaptchaComponentDone(
	sessionToken string,
	domain string,
	adFP string,
	browserFP string,
) error {
	if s.componentDone {
		return nil
	}
	deviceJSON := captchaV2DeviceInfo
	if s.savedProfile != nil && strings.TrimSpace(s.savedProfile.DeviceJSON) != "" {
		deviceJSON = s.savedProfile.DeviceJSON
	}
	if _, err := s.captchaRequest("captchaNotRobot.componentDone", [][2]string{
		{"session_token", sessionToken},
		{"domain", domain},
		{"adFp", adFP},
		{"browser_fp", browserFP},
		{"device", deviceJSON},
		{"access_token", ""},
	}); err != nil {
		return fmt.Errorf("captcha componentDone failed: %w", err)
	}
	s.componentDone = true
	return nil
}

func (s *captchaV2Session) solveCheckboxCaptcha(
	sessionToken string,
	domain string,
	adFP string,
	browserFP string,
	hash string,
	debugInfo string,
) (string, error) {
	if err := s.ensureCaptchaComponentDone(sessionToken, domain, adFP, browserFP); err != nil {
		return "", err
	}

	select {
	case <-s.ctx.Done():
		return "", s.ctx.Err()
	case <-time.After(time.Duration(400+mathrand.Intn(250)) * time.Millisecond):
	}

	check, err := s.performCaptchaCheck(sessionToken, domain, adFP, browserFP, hash, "{}", "[]", debugInfo)
	if err != nil {
		return "", err
	}
	if check.ShowType != "" && !strings.EqualFold(check.ShowType, "checkbox") {
		return "", &captchaV2ShowTypeError{ShowType: check.ShowType}
	}
	if strings.EqualFold(check.Status, "error_limit") {
		return "", errCaptchaV2RateLimit
	}
	if strings.EqualFold(check.Status, "bot") {
		return "", fmt.Errorf("%w: checkbox captcha rejected: status=%s", errCaptchaV2Bot, check.Status)
	}
	if !strings.EqualFold(check.Status, "ok") {
		return "", fmt.Errorf("checkbox captcha rejected: status=%s", check.Status)
	}
	if check.SuccessToken == "" {
		return "", errors.New("captcha success token not found")
	}
	return check.SuccessToken, nil
}

func solveCaptchaPoWV2(ctx context.Context, input string, difficulty int) (string, int) {
	if input == "" || difficulty <= 0 {
		return "", 0
	}
	target := strings.Repeat("0", difficulty)
	buf := make([]byte, 0, len(input)+20)
	buf = append(buf, input...)
	for nonce := 0; nonce <= 10_000_000; nonce++ {
		if nonce&1023 == 0 {
			select {
			case <-ctx.Done():
				return "", 0
			default:
			}
		}
		buf = strconv.AppendInt(buf[:len(input)], int64(nonce), 10)
		sum := sha256.Sum256(buf)
		hashHex := hex.EncodeToString(sum[:])
		if strings.HasPrefix(hashHex, target) {
			return hashHex, nonce
		}
	}
	return "", 0
}

func encodeCaptchaPoWV2(hash string, nonce int) string {
	payload := fmt.Sprintf(`{"hash":"%s","nonce":%d}`, hash, nonce)
	return "v2." + base64.StdEncoding.EncodeToString([]byte(payload))
}

func (s *captchaV2Session) doRaw(
	method string,
	endpoint string,
	form [][2]string,
	extraHeaders map[string]string,
) ([]byte, error) {
	var body []byte
	if form != nil {
		body = []byte(captchaV2EncodeForm(form))
	}
	req, err := fhttp.NewRequestWithContext(s.ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	applyBrowserProfileFhttp(req, s.profile)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Origin", "https://vk.ru")
	req.Header.Set("Referer", "https://vk.ru/")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	req.Header[fhttp.HeaderOrderKey] = captchaV2HeaderOrder
	req.Header[fhttp.PHeaderOrderKey] = captchaV2PHeaderOrder

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("[КАПЧА] v2 close body: %s", closeErr)
		}
	}()
	return io.ReadAll(resp.Body)
}

func captchaV2EncodeForm(values [][2]string) string {
	if len(values) == 0 {
		return ""
	}
	var sb strings.Builder
	for i, kv := range values {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(captchaV2QueryEscape(kv[0]))
		sb.WriteByte('=')
		sb.WriteString(captchaV2QueryEscape(kv[1]))
	}
	return sb.String()
}

func captchaV2QueryEscape(s string) string {
	const upper = "0123456789ABCDEF"
	hexDigits := func(b byte) [3]byte {
		return [3]byte{'%', upper[b>>4], upper[b&0xF]}
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ':
			out = append(out, '+')
		case ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~':
			out = append(out, c)
		default:
			h := hexDigits(c)
			out = append(out, h[:]...)
		}
	}
	return string(out)
}

func captchaV2StringifyAny(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		data, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(data)
	}
}

// applyBrowserProfileFhttp applies browser headers to fhttp requests
func applyBrowserProfileFhttp(req *fhttp.Request, profile Profile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	if profile.SecChUa != "" {
		req.Header.Set("sec-ch-ua", profile.SecChUa)
		req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
		req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
	}
	if strings.Contains(profile.UserAgent, "Firefox/") {
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	} else {
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}
	req.Header.Set("DNT", "1")
}

// VkCaptchaError represents a VK captcha challenge
type VkCaptchaError struct {
	ErrorCode      int
	ErrorMsg       string
	CaptchaSid     string
	RedirectURI    string
	SessionToken   string
	AdFP           string
	RemixStlid     string
	CaptchaTs      string
	CaptchaAttempt string
}

func (e *VkCaptchaError) Error() string {
	if e == nil {
		return "VK captcha required"
	}
	if e.ErrorMsg != "" {
		return fmt.Sprintf("VK captcha error %d: %s", e.ErrorCode, e.ErrorMsg)
	}
	return fmt.Sprintf("VK captcha error %d", e.ErrorCode)
}

func parseVkCaptchaError(errData map[string]interface{}) *VkCaptchaError {
	codeFloat, _ := errData["error_code"].(float64)
	redirectUri, _ := errData["redirect_uri"].(string)
	errorMsg, _ := errData["error_msg"].(string)
	remixStlid := captchaV2StringifyAny(errData["remixstlid"])

	captchaSid, _ := errData["captcha_sid"].(string)
	if captchaSid == "" {
		if sidNum, ok := errData["captcha_sid"].(float64); ok {
			captchaSid = fmt.Sprintf("%.0f", sidNum)
		}
	}

	var sessionToken string
	var adFP string
	if redirectUri != "" {
		if parsed, err := neturl.Parse(redirectUri); err == nil {
			sessionToken = parsed.Query().Get("session_token")
			adFP = parsed.Query().Get("adFp")
			if adFP == "" {
				adFP = parsed.Query().Get("adfp")
			}
		}
	}
	if sessionToken == "" {
		sessionToken, _ = errData["session_token"].(string)
	}

	var captchaTs string
	if tsFloat, ok := errData["captcha_ts"].(float64); ok {
		captchaTs = fmt.Sprintf("%.0f", tsFloat)
	} else if tsStr, ok := errData["captcha_ts"].(string); ok {
		captchaTs = tsStr
	}

	var captchaAttempt string
	if attFloat, ok := errData["captcha_attempt"].(float64); ok {
		captchaAttempt = fmt.Sprintf("%.0f", attFloat)
	} else if attStr, ok := errData["captcha_attempt"].(string); ok {
		captchaAttempt = attStr
	}

	return &VkCaptchaError{
		ErrorCode:      int(codeFloat),
		ErrorMsg:       errorMsg,
		CaptchaSid:     captchaSid,
		RedirectURI:    redirectUri,
		SessionToken:   sessionToken,
		AdFP:           adFP,
		RemixStlid:     remixStlid,
		CaptchaTs:      captchaTs,
		CaptchaAttempt: captchaAttempt,
	}
}
