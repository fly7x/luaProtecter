const source = document.getElementById("source");
const output = document.getElementById("output");
const status = document.getElementById("status");
const protectButton = document.getElementById("protectButton");
const copyButton = document.getElementById("copyButton");
const clearButton = document.getElementById("clearButton");

protectButton.addEventListener("click", async () => {
    const code = source.value;
    if (!code.trim()) {
        status.textContent = "paste a script first";
        return;
    }
    status.textContent = "protecting...";
    protectButton.disabled = true;
    try {
        const res = await fetch("/api/obfuscate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                code,
                vm: document.getElementById("vmMode").checked ? "true" : "false",
                polymorphic: document.getElementById("polymorphic").checked ? "true" : "false"
            })
        });
        const data = await res.json();
        if (!data.success) throw new Error(data.error || "protect failed");
        output.value = data.code;
        status.textContent = "done · " + data.code.length + " bytes";
    } catch (err) {
        status.textContent = String(err.message || err);
    } finally {
        protectButton.disabled = false;
    }
});

copyButton.addEventListener("click", async () => {
    if (!output.value) return;
    await navigator.clipboard.writeText(output.value);
    status.textContent = "copied";
});

clearButton.addEventListener("click", () => {
    source.value = "";
    output.value = "";
    status.textContent = "ready";
});