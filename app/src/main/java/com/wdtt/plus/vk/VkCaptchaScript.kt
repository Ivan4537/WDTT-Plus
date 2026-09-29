package com.wdtt.plus.vk

/** Runs only in allow-listed VK frames. Never inspects login fields, cookies or page text. */
internal object VkCaptchaScript {
    const val CHANNEL = "WDTTInPlaceCaptcha"
    val source = """
        (() => {
          if (window.__wdttCaptchaInstalled || !window.WDTTInPlaceCaptcha) return;
          window.__wdttCaptchaInstalled = true;
          const channel = window.WDTTInPlaceCaptcha;
          if (location.origin === 'https://wdttplus.ru') {
            channel.onmessage = event => {
              try {
                const data = JSON.parse(event.data);
                if (typeof data.pending === 'boolean') {
                  window.__wdttCaptchaPending = data.pending;
                  window.__wdttCaptchaHeartbeat = Date.now();
                }
                if (data.api && typeof window.__wdttApiCaptchaReply === 'function') window.__wdttApiCaptchaReply(data);
              } catch (_) {}
            };
            channel.postMessage('{"state":"runtime"}');
            window.__wdttCaptchaApiAvailable = true;
            return;
          }
          const frame = Math.random().toString(36).slice(2) + Date.now().toString(36);
          let generation = 0, present = false, attempted = false, manual = false;
          let automaticUntil = 0, emptySince = 0, lastState = '', stopped = false;
          const complexSelector = '[class*="SliderCaptcha"], [class*="Kaleidoscope"], [class*="SwipeButton"], [class*="PuzzleCaptcha"]';
          const checkboxSelector = '#not-robot-captcha-checkbox, label[for="not-robot-captcha-checkbox"]';
          const rootSelector = '[class*="Captcha"], [class*="captcha"], [id*="captcha"]';
          const frameSelector = 'iframe[src*="captcha"], iframe[src*="not_robot"]';
          function visible(node) {
            if (!node || !node.isConnected) return false;
            const rect = node.getBoundingClientRect();
            if (rect.width <= 4 || rect.height <= 4 || node.getClientRects().length === 0) return false;
            // A preloaded challenge/error can have its own rectangle while a
            // parent is transparent. Never latch manual mode for that hidden DOM.
            for (let parent = node; parent; parent = parent.parentElement) {
              const style = getComputedStyle(parent);
              if (style.display === 'none' || style.visibility === 'hidden' ||
                  style.visibility === 'collapse' || Number(style.opacity) === 0 ||
                  style.contentVisibility === 'hidden') return false;
            }
            return true;
          }
          function first(selector, root = document) {
            return Array.from(root.querySelectorAll(selector)).find(visible) || null;
          }
          function checkbox() {
            const input = document.getElementById('not-robot-captcha-checkbox');
            if (!input || input.type !== 'checkbox' || input.checked || input.disabled ||
                input.getAttribute('aria-checked') === 'true') return null;
            // VK hides the actual input inside an implicit label (no "for").
            // Only labels associated with this EXACT input are eligible.
            const labels = Array.from(input.labels || []);
            const enclosing = input.closest('label');
            if (enclosing && enclosing.control === input && !labels.includes(enclosing)) labels.push(enclosing);
            for (const label of labels) {
              if (!visible(label)) continue;
              const icon = first('[class*="Checkbox__iconBlock"]', label);
              return icon || label;
            }
            return first(checkboxSelector);
          }
          function send(state) {
            lastState = state;
            channel.postMessage(JSON.stringify({frame, generation, state}));
          }
          function scan() {
            if (stopped) return;
            try {
              const box = checkbox(), complex = first(complexSelector), root = first(rootSelector);
              const iframe = first(frameSelector);
              const captchaPage = /(?:not_robot|captcha)/i.test(location.pathname);
              const found = box || complex || root || iframe || captchaPage;
              if (!found) {
                if (!emptySince) emptySince = Date.now();
                if (present && Date.now() - emptySince < 1500) return;
                present = false; attempted = false; manual = false;
                send('clear');
                return;
              }
              emptySince = 0;
              if (!present) { present = true; generation++; }
              // Empty live regions and decorative "Error" CSS classes are not
              // evidence that VK rejected a check. No page text is read.
              const input = document.getElementById('not-robot-captcha-checkbox');
              const failed = root && Array.from(root.querySelectorAll('[role="alert"]:not(:empty), [class*="CaptchaError"]:not(:empty), [class*="captcha-error"]:not(:empty), [data-testid="captcha-error"]:not(:empty)'))
                .find(node => visible(node) && (!input || !node.contains(input)));
              if (failed) { manual = true; send('error'); }
              else if (complex) { manual = true; send('manual'); }
              else if (manual) send('manual');
              else if (attempted) {
                if (Date.now() >= automaticUntil) { manual = true; send('manual'); }
                else send('automatic');
              } else if (box) send('checkbox');
              else send('waiting'); // Parent iframe detector never clicks through another origin.
            } catch (_) { manual = true; send('error'); }
          }
          channel.onmessage = event => {
            let command;
            try { command = JSON.parse(event.data); } catch (_) { return; }
            if (command.frame !== frame || command.generation !== generation || !present || stopped) return;
            if (command.action === 'manual') { manual = true; scan(); return; }
            if (command.action !== 'click' || attempted || manual || lastState !== 'checkbox') return;
            // Latch BEFORE scheduling; duplicate messages or DOM rerenders cannot click twice.
            attempted = true; automaticUntil = Date.now() + 8000;
            setTimeout(() => {
              if (stopped || manual || !present) return;
              if (document.visibilityState === 'hidden') { manual = true; scan(); return; }
              const box = checkbox();
              if (!box || first(complexSelector)) { manual = true; scan(); return; }
              try { box.click(); } catch (_) { manual = true; }
              scan();
            }, 350);
          };
          function userInput(event) {
            if (event.isTrusted && present) { manual = true; scan(); }
          }
          document.addEventListener('pointerdown', userInput, true);
          document.addEventListener('touchstart', userInput, true);
          document.addEventListener('keydown', userInput, true);
          const timer = setInterval(scan, 500);
          window.addEventListener('pagehide', () => {
            stopped = true; clearInterval(timer); send('clear');
          }, {once: true});
          scan();
        })();
    """.trimIndent()
}
