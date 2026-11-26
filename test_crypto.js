// Test script for crypto verification
async function testCryptoComponents() {
  console.log('=== Testing crypto.getRandomValues ===');
  try {
    const buffer = new Uint8Array(16);
    crypto.getRandomValues(buffer);
    console.log('✓ crypto.getRandomValues works');
  } catch (e) {
    console.error('✗ crypto.getRandomValues failed:', e);
  }
  
  console.log('\n=== Testing crypto.subtle ===');
  try {
    console.log('✓ crypto.subtle is available:', typeof crypto.subtle !== 'undefined');
  } catch (e) {
    console.error('✗ crypto.subtle access failed:', e);
  }
  
  console.log('\n=== Testing PBKDF2 with 600,000 iterations ===');
  try {
    // Create test key
    const testKey = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode('testkey123456789'),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );
    
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iterations = 600000;
    const hashLength = 32; // 256 bits
    
    console.log(`Testing PBKDF2 with ${iterations} iterations and ${hashLength} byte output`);
    
    const start = performance.now();
    const derivedBits = await crypto.subtle.deriveBits(
      testKey,
      salt,
      iterations,
      hashLength
    );
    const end = performance.now();
    
    console.log(`✓ PBKDF2 completed in ${(end - start).toFixed(2)} ms`);
    console.log(`Derived bits length: ${derivedBits.byteLength} bytes`);
    
    // Verify result is valid
    if (derivedBits.byteLength === hashLength) {
      console.log('✓ PBKDF2 test passed');
    } else {
      console.error('✗ PBKDF2 test failed: invalid output length');
    }
  } catch (e) {
    console.error('✗ PBKDF2 test failed:', e);
  }
  
  console.log('\n=== Testing localStorage envelope storage ===');
  try {
    // Create test envelope
    const envelope = {
      hash: 'test_hash',
      salt: 'test_salt',
      iter: 600000,
      hashType: 'PBKDF2-HMAC-SHA256'
    };
    
    // Store in localStorage
    localStorage.setItem('test_envelope', JSON.stringify(envelope));
    
    // Read back
    const stored = JSON.parse(localStorage.getItem('test_envelope'));
    
    console.log('✓ localStorage storage/retrieval test passed');
    console.log('Stored:', envelope);
    console.log('Retrieved:', stored);
    
    // Verify data integrity
    if (JSON.stringify(envelope) === JSON.stringify(stored)) {
      console.log('✓ Storage integrity test passed');
    } else {
      console.error('✗ Storage integrity test failed');
    }
  } catch (e) {
    console.error('✗ localStorage test failed:', e);
  }