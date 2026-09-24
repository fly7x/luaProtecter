(function () {
    var canvas = document.getElementById("bg-grid");
    if (!canvas) return;
    var ctx = canvas.getContext("2d");
    var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var cells = [];
    var cell = 46;
    var hexChars = "0123456789abcdef";

    function size() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        var cols = Math.ceil(canvas.width / cell) + 1;
        var rows = Math.ceil(canvas.height / cell) + 1;
        cells = [];
        for (var r = 0; r < rows; r++) {
            for (var c = 0; c < cols; c++) {
                cells.push({
                    x: c * cell,
                    y: r * cell,
                    a: Math.random() * 0.05,
                    v: byte(),
                    t: Math.random() * Math.PI * 2
                });
            }
        }
    }
    function byte() {
        return hexChars[Math.floor(Math.random() * 16)] + hexChars[Math.floor(Math.random() * 16)];
    }
    window.addEventListener("resize", size);
    size();

    if (reduce) {
        ctx.font = "10px monospace";
        ctx.fillStyle = "rgba(255,255,255,.03)";
        cells.forEach(function (p) { ctx.fillText(p.v, p.x, p.y); });
        return;
    }

    function frame(t) {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.font = "10px 'JetBrains Mono', monospace";
        for (var i = 0; i < cells.length; i++) {
            var p = cells[i];
            var a = 0.025 + 0.02 * Math.sin(t * 0.0004 + p.t);
            if (Math.random() < 0.0025) p.v = byte();
            ctx.fillStyle = "rgba(90,169,255," + Math.max(a, 0) + ")";
            ctx.fillText(p.v, p.x, p.y);
        }
        requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
})();
