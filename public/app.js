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
    return (input.value || '')
      .split(',')
      .map((v) => normalizeExt(v))
      .filter(Boolean);
  }

  function setExtensions(input, values) {
    input.value = Array.from(new Set(values)).join(',');
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
          const next = getExtensions(extInput).filter((ext) => ext !== remove);
          setExtensions(extInput, next);
          renderTags();
        });
      });
    }

    function addOne(raw) {
      const ext = normalizeExt(raw);
      if (!ext) return;
      const next = getExtensions(extInput);
      next.push(ext);
      setExtensions(extInput, next);
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
      if (files.length === 0) {
        list.innerHTML = '';
        return;
      }
      list.innerHTML = files.map((file) => `<li>${file.name} <span class="muted">(${Math.round(file.size / 1024)} KB)</span></li>`).join('');
    });
  }

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

  wireExtensionBuilder();
  wireUploadFileList();
}());
