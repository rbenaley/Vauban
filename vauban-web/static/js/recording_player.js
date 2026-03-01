(function() {
    const video = document.getElementById('recordingVideo');
    if (!video) return;

    const playPauseBtn = document.getElementById('playPauseBtn');
    const restartBtn = document.getElementById('restartBtn');
    const speedSelect = document.getElementById('speedSelect');
    const fullscreenBtn = document.getElementById('fullscreenBtn');
    const progressBar = document.getElementById('progressBar');
    const currentTimeEl = document.getElementById('currentTime');
    const totalTimeEl = document.getElementById('totalTime');

    function formatTime(seconds) {
        const h = Math.floor(seconds / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        const s = Math.floor(seconds % 60);
        return String(h).padStart(2, '0') + ':' +
               String(m).padStart(2, '0') + ':' +
               String(s).padStart(2, '0');
    }

    const playIcon = '<svg class="h-6 w-6" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z" clip-rule="evenodd"/></svg>';
    const pauseIcon = '<svg class="h-6 w-6" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8 7.5a.5.5 0 00-.5.5v4a.5.5 0 001 0V8a.5.5 0 00-.5-.5zm4 0a.5.5 0 00-.5.5v4a.5.5 0 001 0V8a.5.5 0 00-.5-.5z" clip-rule="evenodd"/></svg>';

    playPauseBtn.addEventListener('click', function() {
        if (video.paused) { video.play(); } else { video.pause(); }
    });

    video.addEventListener('play', function() { playPauseBtn.innerHTML = pauseIcon; });
    video.addEventListener('pause', function() { playPauseBtn.innerHTML = playIcon; });

    restartBtn.addEventListener('click', function() {
        video.currentTime = 0;
        video.play();
    });

    speedSelect.addEventListener('change', function() {
        video.playbackRate = parseFloat(this.value);
    });

    fullscreenBtn.addEventListener('click', function() {
        const container = document.getElementById('playerContainer');
        if (document.fullscreenElement) {
            document.exitFullscreen();
        } else {
            (container.requestFullscreen || container.webkitRequestFullscreen).call(container);
        }
    });

    video.addEventListener('loadedmetadata', function() {
        progressBar.max = Math.floor(video.duration);
        totalTimeEl.textContent = formatTime(video.duration);
    });

    video.addEventListener('timeupdate', function() {
        progressBar.value = Math.floor(video.currentTime);
        currentTimeEl.textContent = formatTime(video.currentTime);
    });

    progressBar.addEventListener('input', function() {
        video.currentTime = parseInt(this.value, 10);
    });
})();
