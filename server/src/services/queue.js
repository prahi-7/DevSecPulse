
import Scan from '../models/Scan.js';
import { auditURL } from './audit.js';

const max = () =>
  Math.min(4, Math.max(1, Number(process.env.SCAN_CONCURRENCY) || 2));

const SCAN_TIMEOUT = 15000;

let active = 0;
const pending = [];

export function enqueue(scanId) {
  pending.push(scanId);
  pump();
}

function pump() {
  while (active < max() && pending.length) {
    const id = pending.shift();
    active++;

    run(id)
      .catch(error => console.error('Queue error:', error))
      .finally(() => {
        active--;
        pump();
      });
  }
}

async function run(id) {
  console.log('SCAN STARTED:', id);

  let timer;

  try {
    const scan = await Scan.findByIdAndUpdate(
      id,
      {
        status: 'running',
        startedAt: new Date()
      },
      { new: true }
    );

    if (!scan) return;

    console.log('HTTP AUDIT STARTED:', scan.url);

    const result = await Promise.race([
      auditURL(scan.url),

      new Promise((_, reject) => {
        timer = setTimeout(() => {
          reject(new Error('Scan exceeded 15 seconds'));
        }, SCAN_TIMEOUT);
      })
    ]);

   console.log('HTTP AUDIT FINISHED:', {
       status: result.status,
        error: result.error,
       checks: result.checks
      });

    await Scan.findByIdAndUpdate(id, {
      ...result,
      finishedAt: new Date()
    });

    console.log('SCAN SAVED:', id);

  } catch (error) {
    console.error('SCAN FAILED:', error.message);

    await Scan.findByIdAndUpdate(id, {
      status: 'failed',
      error: error.message,
      finishedAt: new Date()
    }).catch(console.error);

  } finally {
    clearTimeout(timer);
  }
}
