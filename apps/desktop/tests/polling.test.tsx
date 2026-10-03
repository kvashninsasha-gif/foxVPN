import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import {startVisiblePolling} from '../src/polling';
let hidden=false, stop=()=>{};
beforeEach(()=>{vi.useFakeTimers();hidden=false;Object.defineProperty(document,'hidden',{configurable:true,get:()=>hidden});});
afterEach(()=>{stop();vi.useRealTimers();});
it('stops timers while hidden and refreshes immediately when visible',async()=>{
  const poll=vi.fn(async()=>{});stop=startVisiblePolling(poll,3000);
  await vi.advanceTimersByTimeAsync(3000);expect(poll).toHaveBeenCalledTimes(1);
  hidden=true;document.dispatchEvent(new Event('visibilitychange'));
  await vi.advanceTimersByTimeAsync(60000);expect(poll).toHaveBeenCalledTimes(1);
  hidden=false;document.dispatchEvent(new Event('visibilitychange'));
  await vi.advanceTimersByTimeAsync(0);expect(poll).toHaveBeenLastCalledWith(true);
  expect(poll).toHaveBeenCalledTimes(2);
});
it('does not overlap requests and cancels future requests on disposal',async()=>{
  let resolve=()=>{};const poll=vi.fn(()=>new Promise<void>(done=>{resolve=done;}));
  stop=startVisiblePolling(poll,3000);
  await vi.advanceTimersByTimeAsync(15000);expect(poll).toHaveBeenCalledTimes(1);
  stop();resolve();await vi.advanceTimersByTimeAsync(15000);expect(poll).toHaveBeenCalledTimes(1);
});
it('keeps a requested visibility refresh queued until an in-flight request completes',async()=>{
  let resolve=()=>{};const poll=vi.fn(()=>new Promise<void>(done=>{resolve=done;}));
  stop=startVisiblePolling(poll,3000);await vi.advanceTimersByTimeAsync(3000);
  hidden=true;document.dispatchEvent(new Event('visibilitychange'));
  hidden=false;document.dispatchEvent(new Event('visibilitychange'));
  expect(poll).toHaveBeenCalledTimes(1);resolve();await vi.advanceTimersByTimeAsync(0);
  expect(poll).toHaveBeenCalledTimes(2);expect(poll).toHaveBeenLastCalledWith(true);
});
