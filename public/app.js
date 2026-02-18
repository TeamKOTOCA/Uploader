(function attachCopyButtons() {
  const toast = document.createElement('div');
  toast.className = 'toast';
  document.body.appendChild(toast);

  function showToast(message) {
    toast.textContent = message;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 1400);
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
}());
