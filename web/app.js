const source = document.getElementById('source');
const output = document.getElementById('output');
const protectBtn = document.getElementById('protectButton');
const clearBtn = document.getElementById('clearButton');
const copyBtn = document.getElementById('copyButton');
const statusEl = document.getElementById('status');
const spinner = document.getElementById('spinner');
const buttonText = document.getElementById('buttonText');

clearBtn.addEventListener('click', () => {
    source.value = '';
    output.value = '';
    statusEl.textContent = 'Cleared';
});

copyBtn.addEventListener('click', async () => {
    if (!output.value) return;
    try {
        await navigator.clipboard.writeText(output.value);
        copyBtn.textContent = 'Copied!';
        setTimeout(() => copyBtn.textContent = 'Copy', 1200);
    } catch {
        output.select();
        document.execCommand('copy');
        copyBtn.textContent = 'Copied!';
        setTimeout(() => copyBtn.textContent = 'Copy', 1200);
    }
});

protectBtn.addEventListener('click', async () => {
    const code = source.value.trim();
    if (!code) {
        statusEl.textContent = 'Please paste some code.';
        source.focus();
        return;
    }
    
    protectBtn.disabled = true;
    buttonText.classList.add('hidden');
    spinner.classList.remove('hidden');
    statusEl.textContent = 'Protecting...';
    
    const payload = {
        code: code,
        options: {
            vm: document.getElementById('vmMode').checked,
            polymorphic: document.getElementById('polymorphic').checked
        }
    };
    
    try {
        const resp = await fetch('/api/obfuscate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await resp.json();
        if (!resp.ok || !data.success) {
            throw new Error(data.error || 'Unknown error');
        }
        output.value = data.code;
        statusEl.textContent = 'Protection complete!';
    } catch (err) {
        output.value = '';
        statusEl.textContent = 'Error: ' + err.message;
    } finally {
        protectBtn.disabled = false;
        buttonText.classList.remove('hidden');
        spinner.classList.add('hidden');
    }
});