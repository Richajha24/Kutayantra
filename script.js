/**
 * KŪṬAYANTRA · Diffie–Hellman Key Exchange Simulator
 * Core JavaScript Logic & Modular Exponentiation Engine
 * 
 * Includes:
 * - Native BigInt modular arithmetic (square-and-multiply algorithm)
 * - Dynamic parameter validation and secret clamping
 * - 6-stage interactive educational animation timeline
 * - Real-time spy panel and narrative activity log updating
 * - Live math explainer algebraic binder
 */

(function () {
  'use me strict';

  // --- 1. DEFAULT CONSTANTS ---
  const DEFAULTS = {
    P: 23n,
    G: 5n,
    A: 6n,
    B: 15n
  };

  // --- 2. STATE OBJECT ---
  const state = {
    p: DEFAULTS.P,
    g: DEFAULTS.G,
    a: DEFAULTS.A,
    b: DEFAULTS.B,
    A: null, // Computed public value A = g^a mod p
    B: null, // Computed public value B = g^b mod p
    sharedKeyMagadha: null,
    sharedKeyAvanti: null,
    isAnimating: false,
    currentStep: 0
  };

  // --- 3. DOM ELEMENT REFERENCES ---
  const DOM = {
    // Inputs & Buttons
    inputP: document.getElementById('input-p'),
    inputG: document.getElementById('input-g'),
    primeStatus: document.getElementById('prime-status'),
    generatorStatus: document.getElementById('generator-status'),
    validationAlert: document.getElementById('validation-alert'),
    btnBegin: document.getElementById('btn-begin'),
    btnRandomize: document.getElementById('btn-randomize'),
    btnReset: document.getElementById('btn-reset'),

    // Magadha Court
    sliderA: document.getElementById('slider-a'),
    valADisplay: document.getElementById('val-a-display'),
    magadhaCalcDisplay: document.getElementById('magadha-calc-display'),
    magadhaKeyDisplay: document.getElementById('magadha-key-display'),

    // Avanti Court
    sliderB: document.getElementById('slider-b'),
    valBDisplay: document.getElementById('val-b-display'),
    avantiCalcDisplay: document.getElementById('avanti-calc-display'),
    avantiKeyDisplay: document.getElementById('avanti-key-display'),

    // Watched Road & Messengers
    messengerA: document.getElementById('messenger-a'),
    messengerB: document.getElementById('messenger-b'),
    tokenAText: document.getElementById('token-a-text'),
    tokenBText: document.getElementById('token-b-text'),
    spyInterceptFlash: document.getElementById('spy-intercept-flash'),
    stageStepNum: document.getElementById('stage-step-num'),
    stageStepText: document.getElementById('stage-step-text'),

    // Spy Panel
    spyValP: document.getElementById('spy-val-p'),
    spyValG: document.getElementById('spy-val-g'),
    spyValA: document.getElementById('spy-val-A'),
    spyValB: document.getElementById('spy-val-B'),
    spyVala: document.getElementById('spy-val-a'),
    spyValb: document.getElementById('spy-val-b'),
    spyValK: document.getElementById('spy-val-K'),

    // Sealed Agreement Panel
    sealedAgreement: document.getElementById('sealed-agreement'),
    finalSharedKeyDisplay: document.getElementById('final-shared-key-display'),
    finalMagadhaDerived: document.getElementById('final-magadha-derived'),
    finalAvantiDerived: document.getElementById('final-avanti-derived'),

    // Activity Log & Math Proof
    logList: document.getElementById('log-list'),
    magadhaLiveMath: document.getElementById('magadha-live-math'),
    avantiLiveMath: document.getElementById('avanti-live-math')
  };

  // --- 4. CRYPTOGRAPHIC MATHEMATICS ENGINE ---

  /**
   * Native BigInt Modular Exponentiation using Square-and-Multiply.
   * Computes (base ^ exponent) % modulus in O(log exponent) time.
   * 
   * @param {bigint} base 
   * @param {bigint} exponent 
   * @param {bigint} modulus 
   * @returns {bigint}
   */
  function modPow(base, exponent, modulus) {
    if (modulus === 1n) return 0n;
    let result = 1n;
    let b = ((base % modulus) + modulus) % modulus;
    let e = exponent;

    while (e > 0n) {
      if (e % 2n === 1n) {
        result = (result * b) % modulus;
      }
      e = e / 2n;
      b = (b * b) % modulus;
    }

    return result;
  }

  /**
   * Simple Primality Check for display badge status.
   * @param {bigint} n 
   * @returns {boolean}
   */
  function isPrime(n) {
    if (n <= 1n) return false;
    if (n <= 3n) return true;
    if (n % 2n === 0n || n % 3n === 0n) return false;

    let i = 5n;
    while (i * i <= n) {
      if (n % i === 0n || n % (i + 2n) === 0n) return false;
      i += 6n;
    }
    return true;
  }

  // --- 5. VALIDATION & PARAMETER MANAGEMENT ---

  /**
   * Reads inputs from DOM, validates bounds, updates slider limits.
   * @returns {boolean} isValid
   */
  function validateAndSyncParameters() {
    let pVal = parseInt(DOM.inputP.value, 10);
    let gVal = parseInt(DOM.inputG.value, 10);

    let errors = [];

    // Validate p
    if (isNaN(pVal) || pVal < 5) {
      errors.push("Prime modulus (p) must be an integer at least 5.");
      DOM.primeStatus.textContent = "Invalid p ✗";
      DOM.primeStatus.className = "badge-status invalid";
      pVal = 5;
    } else {
      let BigP = BigInt(pVal);
      if (isPrime(BigP)) {
        DOM.primeStatus.textContent = "Prime ✓";
        DOM.primeStatus.className = "badge-status valid";
      } else {
        DOM.primeStatus.textContent = "Composite (Warn)";
        DOM.primeStatus.className = "badge-status invalid";
      }
    }

    // Validate g
    if (isNaN(gVal) || gVal < 2) {
      errors.push("Base generator (g) must be at least 2.");
      DOM.generatorStatus.textContent = "Invalid g ✗";
      DOM.generatorStatus.className = "badge-status invalid";
    } else if (gVal >= pVal) {
      errors.push(`Base generator (g) should be less than prime modulus p (${pVal}).`);
      DOM.generatorStatus.textContent = "g ≥ p ✗";
      DOM.generatorStatus.className = "badge-status invalid";
    } else {
      DOM.generatorStatus.textContent = "Valid Base ✓";
      DOM.generatorStatus.className = "badge-status valid";
    }

    // Display validation messages
    if (errors.length > 0) {
      DOM.validationAlert.textContent = errors.join(" ");
      DOM.validationAlert.classList.remove('hidden');
    } else {
      DOM.validationAlert.textContent = "";
      DOM.validationAlert.classList.add('hidden');
    }

    // Update BigInt state
    state.p = BigInt(pVal);
    state.g = BigInt(gVal >= 2 ? gVal : 2);

    // Update Slider Ranges (1 <= secret <= p - 2)
    let maxSecret = pVal - 2;
    if (maxSecret < 1) maxSecret = 1;

    DOM.sliderA.max = maxSecret;
    DOM.sliderB.max = maxSecret;

    // Clamp secret values if they exceed maxSecret
    let aVal = parseInt(DOM.sliderA.value, 10);
    let bVal = parseInt(DOM.sliderB.value, 10);

    if (aVal > maxSecret) {
      aVal = maxSecret;
      DOM.sliderA.value = aVal;
    }
    if (bVal > maxSecret) {
      bVal = maxSecret;
      DOM.sliderB.value = bVal;
    }

    state.a = BigInt(aVal);
    state.b = BigInt(bVal);

    // Update Secret badges
    DOM.valADisplay.textContent = `a = ${state.a}`;
    DOM.valBDisplay.textContent = `b = ${state.b}`;

    // Update live proof binder text
    updateMathExplainer();

    return errors.length === 0;
  }

  /**
   * Computes instant values for A, B and shared keys.
   */
  function calculateAllValues() {
    state.A = modPow(state.g, state.a, state.p);
    state.B = modPow(state.g, state.b, state.p);

    state.sharedKeyMagadha = modPow(state.B, state.a, state.p);
    state.sharedKeyAvanti = modPow(state.A, state.b, state.p);
  }

  // --- 6. INTERACTIVE NARRATIVE LOG & MATH EXPLAINER ---

  /**
   * Adds an entry to the live transcript terminal.
   * @param {string} text 
   */
  function addLogEntry(text) {
    const li = document.createElement('li');
    li.className = 'log-entry';
    li.textContent = text;
    DOM.logList.appendChild(li);
    DOM.logList.parentElement.scrollTop = DOM.logList.parentElement.scrollHeight;
  }

  /**
   * Clears the narrative activity log.
   */
  function clearLog() {
    DOM.logList.innerHTML = '';
  }

  /**
   * Updates the step-by-step mathematical proof section dynamically.
   */
  function updateMathExplainer() {
    calculateAllValues();

    const p = state.p;
    const g = state.g;
    const a = state.a;
    const b = state.b;
    const ab = a * b;

    const gPowAb = modPow(g, ab, p);

    DOM.magadhaLiveMath.innerHTML = 
      `K<sub>Magadha</sub> = (${g}<sup>${b}</sup>)<sup>${a}</sup> mod ${p} = ${g}<sup>${ab}</sup> mod ${p} = <strong>${state.sharedKeyMagadha}</strong>`;

    DOM.avantiLiveMath.innerHTML = 
      `K<sub>Avanti</sub> = (${g}<sup>${a}</sup>)<sup>${b}</sup> mod ${p} = ${g}<sup>${ab}</sup> mod ${p} = <strong>${state.sharedKeyAvanti}</strong>`;
  }

  // --- 7. STAGED EDUCATIONAL ANIMATION CONTROLLER ---

  /**
   * Helper function for async sleeping in animations.
   * Respects prefers-reduced-motion settings.
   * @param {number} ms 
   */
  function sleep(ms) {
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    return new Promise(resolve => setTimeout(resolve, reducedMotion ? 50 : ms));
  }

  /**
   * Resets the simulator board state before a new exchange.
   */
  function resetBoardVisuals() {
    DOM.magadhaCalcDisplay.innerHTML = '<span class="placeholder-state">A = ?</span>';
    DOM.avantiCalcDisplay.innerHTML = '<span class="placeholder-state">B = ?</span>';
    
    DOM.magadhaKeyDisplay.innerHTML = '<span class="placeholder-state">K<sub>Magadha</sub> = B<sup>a</sup> mod p = ?</span>';
    DOM.avantiKeyDisplay.innerHTML = '<span class="placeholder-state">K<sub>Avanti</sub> = A<sup>b</sup> mod p = ?</span>';

    DOM.messengerA.classList.add('hidden');
    DOM.messengerB.classList.add('hidden');
    DOM.messengerA.style.left = '5%';
    DOM.messengerB.style.left = '80%';

    DOM.spyInterceptFlash.classList.add('hidden');

    DOM.sealedAgreement.classList.add('hidden');

    DOM.spyValP.textContent = state.p.toString();
    DOM.spyValG.textContent = state.g.toString();
    DOM.spyValA.textContent = "?";
    DOM.spyValB.textContent = "?";
    DOM.spyVala.textContent = "••• [PROTECTED]";
    DOM.spyValb.textContent = "••• [PROTECTED]";
    DOM.spyValK.textContent = "••• [PROTECTED]";

    DOM.stageStepNum.textContent = "READY";
    DOM.stageStepText.textContent = "Click 'Begin the Exchange' to start simulation";
  }

  /**
   * Runs the 6-stage educational animation sequence.
   */
  async function runExchangeAnimation() {
    if (state.isAnimating) return;
    if (!validateAndSyncParameters()) return;

    state.isAnimating = true;
    DOM.btnBegin.disabled = true;
    DOM.btnRandomize.disabled = true;
    DOM.btnReset.disabled = true;

    clearLog();
    resetBoardVisuals();
    calculateAllValues();

    // STEP 1: PUBLIC DECREE
    DOM.stageStepNum.textContent = "STEP 1 OF 6";
    DOM.stageStepText.textContent = "1 · Public Decree Proclaimed";
    addLogEntry(`01 — Public decree proclaimed: p = ${state.p}, g = ${state.g}. Anyone on the road can observe these parameters.`);
    await sleep(1500);

    // STEP 2: PRIVATE COUNSEL
    DOM.stageStepNum.textContent = "STEP 2 OF 6";
    DOM.stageStepText.textContent = "2 · Private Counsel Selection";
    addLogEntry(`02 — Magadha secretly selects private exponent a = ${state.a}. Known only inside Magadha.`);
    addLogEntry(`03 — Avanti secretly selects private exponent b = ${state.b}. Known only inside Avanti.`);
    await sleep(1500);

    // STEP 3: PUBLIC VALUE COMPUTATION
    DOM.stageStepNum.textContent = "STEP 3 OF 6";
    DOM.stageStepText.textContent = "3 · Public Values Computed";
    
    DOM.magadhaCalcDisplay.innerHTML = 
      `<span class="mono">A = ${state.g}<sup>${state.a}</sup> mod ${state.p} = <strong>${state.A}</strong></span>`;
    addLogEntry(`04 — Magadha computes public value A = ${state.g}^${state.a} mod ${state.p} = ${state.A}.`);
    
    await sleep(1000);

    DOM.avantiCalcDisplay.innerHTML = 
      `<span class="mono">B = ${state.g}<sup>${state.b}</sup> mod ${state.p} = <strong>${state.B}</strong></span>`;
    addLogEntry(`05 — Avanti computes public value B = ${state.g}^${state.b} mod ${state.p} = ${state.B}.`);

    await sleep(1500);

    // STEP 4: MESSENGER CROSSING
    DOM.stageStepNum.textContent = "STEP 4 OF 6";
    DOM.stageStepText.textContent = "4 · Messengers Crossing the Watched Road";
    
    // Messenger A (Magadha -> Avanti)
    DOM.tokenAText.textContent = `A = ${state.A}`;
    DOM.messengerA.classList.remove('hidden');
    DOM.messengerA.style.left = '5%';
    addLogEntry(`06 — Messenger dispatched from Magadha carrying A = ${state.A} across the watched road.`);

    await sleep(400);
    DOM.messengerA.style.left = '45%';
    await sleep(800);

    // Spy Intercepts A
    DOM.spyInterceptFlash.classList.remove('hidden');
    DOM.spyInterceptFlash.textContent = `SPY OBSERVED A = ${state.A}`;
    DOM.spyValA.textContent = state.A.toString();
    await sleep(800);

    DOM.messengerA.style.left = '85%';
    await sleep(800);

    // Messenger B (Avanti -> Magadha)
    DOM.tokenBText.textContent = `B = ${state.B}`;
    DOM.messengerB.classList.remove('hidden');
    DOM.messengerB.style.left = '85%';
    addLogEntry(`07 — Messenger dispatched from Avanti carrying B = ${state.B} across the watched road.`);

    await sleep(400);
    DOM.messengerB.style.left = '45%';
    await sleep(800);

    // Spy Intercepts B
    DOM.spyInterceptFlash.textContent = `SPY OBSERVED B = ${state.B}`;
    DOM.spyValB.textContent = state.B.toString();
    await sleep(800);

    DOM.messengerB.style.left = '5%';
    await sleep(800);

    DOM.spyInterceptFlash.classList.add('hidden');

    // STEP 5: INDEPENDENT DERIVATION
    DOM.stageStepNum.textContent = "STEP 5 OF 6";
    DOM.stageStepText.textContent = "5 · Independent Shared Key Derivation";

    DOM.magadhaKeyDisplay.innerHTML = 
      `<span class="mono">K = ${state.B}<sup>${state.a}</sup> mod ${state.p} = <strong>${state.sharedKeyMagadha}</strong></span>`;
    addLogEntry(`08 — Magadha receives B = ${state.B} and computes shared secret key K = ${state.B}^${state.a} mod ${state.p} = ${state.sharedKeyMagadha}.`);

    await sleep(1000);

    DOM.avantiKeyDisplay.innerHTML = 
      `<span class="mono">K = ${state.A}<sup>${state.b}</sup> mod ${state.p} = <strong>${state.sharedKeyAvanti}</strong></span>`;
    addLogEntry(`09 — Avanti receives A = ${state.A} and computes shared secret key K = ${state.A}^${state.b} mod ${state.p} = ${state.sharedKeyAvanti}.`);

    await sleep(1500);

    // STEP 6: AGREEMENT & SEALED RESULT
    DOM.stageStepNum.textContent = "STEP 6 OF 6";
    DOM.stageStepText.textContent = "6 · Agreement Confirmed";

    addLogEntry(`10 — Agreement confirmed! Both courts derived the exact same shared secret key: ${state.sharedKeyMagadha}.`);
    addLogEntry(`11 — Spy visible data logged: p = ${state.p}, g = ${state.g}, A = ${state.A}, B = ${state.B}. Private secrets (a, b) remain safe.`);

    DOM.finalSharedKeyDisplay.textContent = state.sharedKeyMagadha.toString();
    DOM.finalMagadhaDerived.textContent = state.sharedKeyMagadha.toString();
    DOM.finalAvantiDerived.textContent = state.sharedKeyAvanti.toString();

    DOM.sealedAgreement.classList.remove('hidden');
    DOM.sealedAgreement.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    state.isAnimating = false;
    DOM.btnBegin.disabled = false;
    DOM.btnRandomize.disabled = false;
    DOM.btnReset.disabled = false;
  }

  // --- 8. ACTION HANDLERS ---

  /**
   * Randomizes secret exponents a and b to valid range (1 <= secret <= p - 2).
   */
  function handleRandomizeSecrets() {
    validateAndSyncParameters();
    const maxSecret = Number(state.p) - 2;
    if (maxSecret < 1) return;

    const randA = Math.floor(Math.random() * maxSecret) + 1;
    const randB = Math.floor(Math.random() * maxSecret) + 1;

    DOM.sliderA.value = randA;
    DOM.sliderB.value = randB;

    validateAndSyncParameters();
    resetBoardVisuals();

    addLogEntry(`Secret exponents randomized: Magadha (a = ${randA}), Avanti (b = ${randB}).`);
  }

  /**
   * Resets simulator parameters to project default demonstration values.
   * Default: p = 23, g = 5, a = 6, b = 15.
   */
  function handleResetDefaults() {
    DOM.inputP.value = DEFAULTS.P.toString();
    DOM.inputG.value = DEFAULTS.G.toString();
    DOM.sliderA.value = DEFAULTS.A.toString();
    DOM.sliderB.value = DEFAULTS.B.toString();

    validateAndSyncParameters();
    clearLog();
    resetBoardVisuals();
    addLogEntry("Simulator reset to default parameters (p = 23, g = 5, a = 6, b = 15).");
  }

  // --- 9. EVENT LISTENERS SETUP ---
  function initEventListeners() {
    // Inputs & Sliders
    DOM.inputP.addEventListener('input', () => {
      validateAndSyncParameters();
      resetBoardVisuals();
    });

    DOM.inputG.addEventListener('input', () => {
      validateAndSyncParameters();
      resetBoardVisuals();
    });

    DOM.sliderA.addEventListener('input', () => {
      validateAndSyncParameters();
      resetBoardVisuals();
    });

    DOM.sliderB.addEventListener('input', () => {
      validateAndSyncParameters();
      resetBoardVisuals();
    });

    // Buttons
    DOM.btnBegin.addEventListener('click', runExchangeAnimation);
    DOM.btnRandomize.addEventListener('click', handleRandomizeSecrets);
    DOM.btnReset.addEventListener('click', handleResetDefaults);
  }

  // --- 10. INITIALIZATION ---
  function init() {
    initEventListeners();
    validateAndSyncParameters();
    resetBoardVisuals();
    addLogEntry("00 — Protocol initialized with default parameters. Ready for exchange.");
  }

  // Run init on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
