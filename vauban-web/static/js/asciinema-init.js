document.addEventListener('DOMContentLoaded', function() {
    var el = document.getElementById('player');
    if (!el) return;
    var src = el.getAttribute('data-src');
    if (!src) return;
    AsciinemaPlayer.create(src, el, {
        theme: 'monokai',
        fit: 'width',
        idleTimeLimit: 2
    });
});
