/**
 * Shaka Player initialization for segmented recording playback.
 *
 * Reads the DASH manifest URL from the video element's data-manifest attribute.
 * Requires shaka-player.compiled.js to be loaded first.
 */
(function() {
    "use strict";
    shaka.polyfill.installAll();
    var video = document.getElementById("recordingVideo");
    if (!video) return;
    var manifest = video.getAttribute("data-manifest");
    if (!manifest) return;

    var player = new shaka.Player();

    player.addEventListener("error", function(event) {
        console.error("Shaka error event:", event.detail.code, event.detail.data);
    });

    player.attach(video).then(function() {
        return player.load(manifest);
    }).catch(function(e) {
        console.error("Shaka load failed:", e.code, e.data);
        console.error("Manifest URL:", manifest);
    });
})();
