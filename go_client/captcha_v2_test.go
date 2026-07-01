package main

import (
	"errors"
	"testing"
)

func TestParseCaptchaV2PageUsesActualScriptMetadata(t *testing.T) {
	html := `
		<html>
			<head>
				<script src='//static.vk.ru/vkid/1.1.1359/not_robot_captcha.js?hash=abc'></script>
				<script>
					window.init = {"data":{"show_captcha_type":"slider","captcha_settings":[{"type":"slider","settings":"{\"nested\":true}"}]}};
					const powInput = "abc";
					const difficulty = 3;
				</script>
			</head>
		</html>`

	page, err := parseCaptchaV2Page(html)
	if err != nil {
		t.Fatalf("parseCaptchaV2Page returned error: %v", err)
	}
	if page.ScriptURL != "https://static.vk.ru/vkid/1.1.1359/not_robot_captcha.js?hash=abc" {
		t.Fatalf("unexpected script URL: %s", page.ScriptURL)
	}
	if page.ScriptVersion != "1.1.1359" {
		t.Fatalf("unexpected script version: %s", page.ScriptVersion)
	}
	if page.Domain != "vk.ru" {
		t.Fatalf("unexpected domain: %s", page.Domain)
	}
	if page.PowInput != "abc" || page.PowDifficulty != 3 {
		t.Fatalf("unexpected pow settings: input=%q difficulty=%d", page.PowInput, page.PowDifficulty)
	}
	if page.Init == nil || page.Init.Data.ShowCaptchaType != "slider" {
		t.Fatalf("unexpected init payload: %#v", page.Init)
	}
}

func TestExtractCaptchaV2WindowInitWithNestedObject(t *testing.T) {
	html := `
		<script>
			window.init = {"data":{"captcha_settings":[{"type":"slider","settings":"{\"a\":{\"b\":1}}"}]}};
			window.after = true;
		</script>`

	got, err := extractCaptchaV2WindowInit(html)
	if err != nil {
		t.Fatalf("extractCaptchaV2WindowInit returned error: %v", err)
	}
	want := `{"data":{"captcha_settings":[{"type":"slider","settings":"{\"a\":{\"b\":1}}"}]}}`
	if got != want {
		t.Fatalf("unexpected init json:\nwant %s\ngot  %s", want, got)
	}
}

func TestInferCaptchaV2DomainPrefersChallengeDomain(t *testing.T) {
	got := inferCaptchaV2Domain(
		"https://id.vk.ru/captcha?session_token=abc&domain=vk.com",
		"https://static.vk.ru/vkid/1.1.1359/not_robot_captcha.js",
	)
	if got != "vk.com" {
		t.Fatalf("unexpected domain: %s", got)
	}
}

func TestInferCaptchaV2DomainFallsBackToScriptURL(t *testing.T) {
	got := inferCaptchaV2Domain("", "https://static.vk.com/vkid/1.1.1367/not_robot_captcha.js")
	if got != "vk.com" {
		t.Fatalf("unexpected domain: %s", got)
	}
}

func TestEncodeCaptchaPoWV2(t *testing.T) {
	got := encodeCaptchaPoWV2("00abc", 42)
	want := "v2.eyJoYXNoIjoiMDBhYmMiLCJub25jZSI6NDJ9"
	if got != want {
		t.Fatalf("unexpected PoW token: %s", got)
	}
}

func TestParseVkCaptchaErrorReadsAdFP(t *testing.T) {
	got := parseVkCaptchaError(map[string]interface{}{
		"error_code":   float64(14),
		"redirect_uri": "https://id.vk.com/captcha?session_token=session&adFp=fingerprint&domain=vk.com",
		"remixstlid":   "tmp-user",
	})
	if got.SessionToken != "session" || got.AdFP != "fingerprint" || got.RemixStlid != "tmp-user" {
		t.Fatalf("unexpected captcha challenge: %#v", got)
	}
}

func TestCaptchaV2SessionAdFPUsesChallengeValue(t *testing.T) {
	got, err := captchaV2SessionAdFP(" challenge-fp ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "challenge-fp" {
		t.Fatalf("unexpected adFp: %q", got)
	}
}

func TestCaptchaV2SessionAdFPGeneratesURLSafeValue(t *testing.T) {
	got, err := captchaV2SessionAdFP("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 22 {
		t.Fatalf("unexpected generated adFp length: %d (%q)", len(got), got)
	}
	for _, ch := range got {
		if !(ch >= 'A' && ch <= 'Z') && !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') && ch != '-' && ch != '_' {
			t.Fatalf("generated adFp is not base64url-safe: %q", got)
		}
	}
}

func TestParseCaptchaV2SettingsAcceptsMapPayload(t *testing.T) {
	got, err := parseCaptchaV2Settings(map[string]any{
		"response": map[string]any{
			"show_captcha_type": "slider",
			"captcha_settings": map[string]any{
				"slider": map[string]any{"variant": "fresh"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ShowType != "slider" || got.ByType["slider"] != `{"variant":"fresh"}` {
		t.Fatalf("unexpected settings: %#v", got)
	}
}

func TestParseCaptchaV2SettingsAcceptsStringPayload(t *testing.T) {
	got, err := parseCaptchaV2Settings(map[string]any{
		"response": map[string]any{
			"captcha_settings": `[{"type":"slider","settings":"live"}]`,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ByType["slider"] != "live" {
		t.Fatalf("unexpected settings: %#v", got)
	}
}

func TestCaptchaSolveStageUsesFreshChallengePerFallback(t *testing.T) {
	want := []string{"Auto WebView", "Auto WebView", "Go v2", "Manual WebView"}
	for attempt, expected := range want {
		got, ok := captchaSolveStage(attempt + 1)
		if !ok || got != expected {
			t.Fatalf("attempt %d: got %q ok=%v, want %q", attempt+1, got, ok, expected)
		}
	}
	if got := captchaSolveStageCount(); got != len(want) {
		t.Fatalf("unexpected stage count: got %d, want %d", got, len(want))
	}
	if _, ok := captchaSolveStage(5); ok {
		t.Fatal("unexpected fifth captcha stage")
	}
}

func TestCaptchaStageResetsAfterSolverSuccess(t *testing.T) {
	for attempt := 1; attempt <= captchaSolveStageCount(); attempt++ {
		if got := captchaStageAfterSolverSuccess(attempt); got != 1 {
			t.Fatalf("success after stage %d should restart at Auto WebView, got %d", attempt, got)
		}
	}
	got, softFailures := captchaNextStageAfterSolverFailure(2, errors.New("hard failure"), 0)
	if got != 3 || softFailures != 0 {
		t.Fatalf("failure after stage 2 should continue at stage 3, got %d", got)
	}
}

func TestCaptchaAutoSoftFailureRetriesFreshAuto(t *testing.T) {
	got, softFailures := captchaNextStageAfterSolverFailure(
		1,
		errors.New("request fresh captcha challenge: Auto WebView: webview captcha failed: error:auto_no_result"),
		0,
	)
	if got != 1 || softFailures != 1 {
		t.Fatalf("soft auto failure should retry fresh Auto WebView, got stage=%d soft=%d", got, softFailures)
	}

	got, softFailures = captchaNextStageAfterSolverFailure(
		1,
		errors.New("request fresh captcha challenge: Auto WebView: webview captcha failed: error:auto_check_not_sent"),
		captchaAutoSoftFailureLimit,
	)
	if got != 2 || softFailures != captchaAutoSoftFailureLimit {
		t.Fatalf("soft auto failures after limit should advance, got stage=%d soft=%d", got, softFailures)
	}
}

func TestBuildCaptchaRetryDataWithoutCaptchaSid(t *testing.T) {
	got := buildCaptchaRetryData(
		"join-code",
		"Test+User",
		"anon-token",
		&VkCaptchaError{RemixStlid: "tmp/user"},
		"success/token",
	)
	want := "vk_join_link=https://vk.ru/call/join/join-code&name=Test+User&success_token=success%2Ftoken&access_token=anon-token&remixstlid=tmp%2Fuser"
	if got != want {
		t.Fatalf("unexpected retry data:\nwant %s\ngot  %s", want, got)
	}
}
