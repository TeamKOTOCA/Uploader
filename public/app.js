(function attachUiHelpers() {
  const toast = document.createElement('div');
  toast.className = 'toast';
  document.body.appendChild(toast);

  function showToast(message) {
    toast.textContent = message;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 1400);
  }

  function normalizeExt(value) {
    return String(value || '').trim().toLowerCase().replace(/^\./, '').replace(/[^a-z0-9]/g, '');
  }
  function getExtensions(input) {
    return (input.value || '').split(',').map((v) => normalizeExt(v)).filter(Boolean);
  }
  function setExtensions(input, values) {
    input.value = Array.from(new Set(values)).join(',');
  }

  function wireTabs() {
    const root = document.querySelector('[data-tabs]');
    if (!root) return;
    const buttons = Array.from(root.querySelectorAll('[data-tab-target]'));
    const panels = Array.from(root.querySelectorAll('[data-tab-panel]'));
    function activate(id) {
      panels.forEach((p) => { p.style.display = p.getAttribute('data-tab-panel') === id ? 'block' : 'none'; });
      buttons.forEach((b) => b.classList.toggle('active', b.getAttribute('data-tab-target') === id));
    }
    buttons.forEach((button) => button.addEventListener('click', () => activate(button.getAttribute('data-tab-target'))));
    if (buttons[0]) activate(buttons[0].getAttribute('data-tab-target'));
  }

  function wireExtensionBuilder() {
    const extInput = document.getElementById('allowedExtensionsInput');
    const candidateInput = document.getElementById('extCandidate');
    const selectedBox = document.getElementById('selectedExtensions');
    if (!extInput || !candidateInput || !selectedBox) return;

    function renderTags() {
      const items = getExtensions(extInput);
      selectedBox.innerHTML = items.map((ext) => `<button type="button" class="tag" data-remove-ext="${ext}">.${ext} ×</button>`).join('');
      selectedBox.querySelectorAll('[data-remove-ext]').forEach((button) => {
        button.addEventListener('click', () => {
          const remove = button.getAttribute('data-remove-ext');
          setExtensions(extInput, getExtensions(extInput).filter((ext) => ext !== remove));
          renderTags();
        });
      });
    }

    function addOne(raw) {
      const ext = normalizeExt(raw);
      if (!ext) return;
      setExtensions(extInput, getExtensions(extInput).concat(ext));
      renderTags();
      candidateInput.value = '';
    }

    document.querySelectorAll('[data-ext-preset]').forEach((button) => {
      button.addEventListener('click', () => {
        const preset = (button.getAttribute('data-ext-preset') || '').split(',').map((v) => normalizeExt(v)).filter(Boolean);
        setExtensions(extInput, getExtensions(extInput).concat(preset));
        renderTags();
      });
    });
    const addBtn = document.querySelector('[data-add-extension]');
    if (addBtn) addBtn.addEventListener('click', () => addOne(candidateInput.value));
    candidateInput.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        addOne(candidateInput.value);
      }
    });
    extInput.addEventListener('input', renderTags);
    renderTags();
  }

  function wireUploadFileList() {
    const input = document.getElementById('uploadFilesInput');
    const list = document.getElementById('selectedUploadFiles');
    if (!input || !list) return;
    input.addEventListener('change', () => {
      const files = Array.from(input.files || []);
      list.innerHTML = files.map((file) => `<li>${file.name} <span class="muted">(${Math.round(file.size / 1024)} KB)</span></li>`).join('');
    });
  }

  async function enablePush() {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
      showToast('このブラウザはPush通知に非対応です');
      return;
    }
    const perm = await Notification.requestPermission();
    if (perm !== 'granted') {
      showToast('通知が許可されていません');
      return;
    }
    const keyRes = await fetch('/push/vapid-public-key');
    if (!keyRes.ok) {
      showToast('Push通知が未設定です');
      return;
    }
    const { key } = await keyRes.json();
    const reg = await navigator.serviceWorker.register('/assets/sw.js');
    const urlBase64ToUint8Array = (base64String) => {
      const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
      const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
      const rawData = atob(base64);
      return Uint8Array.from([...rawData].map((c) => c.charCodeAt(0)));
    };
    const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlBase64ToUint8Array(key) });
    await fetch('/push/subscribe', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ subscription: sub }) });
    showToast('Push通知を有効化しました');
  }

  const enablePushBtn = document.getElementById('enablePushBtn');
  if (enablePushBtn) enablePushBtn.addEventListener('click', () => enablePush().catch(() => showToast('Push設定に失敗しました')));

  document.querySelectorAll('.js-copy').forEach((button) => {
    button.addEventListener('click', async () => {
      const text = button.getAttribute('data-copy');
      const absolute = new URL(text, window.location.origin).toString();
      try {
        await navigator.clipboard.writeText(absolute);
        showToast('リンクをコピーしました');
      } catch (_) {
        showToast('コピーに失敗しました');
      }
    });
  });

  wireTabs();
  wireExtensionBuilder();
  wireUploadFileList();
}());
