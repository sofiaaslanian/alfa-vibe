#!/usr/bin/env python3
from __future__ import annotations

import argparse, asyncio, json, statistics, time, uuid
from collections import Counter

import httpx

PAYLOADS = [
    "Клиент Иван Петров, email ivan.petrov@mail.ru, телефон +7 (999) 123-45-67.",
    "Дата рождения клиента 12.04.1995, паспорт 45 10 123456, код подразделения 770-001.",
    "Мой адрес: Москва, ул. Лесная, д. 10, кв. 5. ИНН 500100732259.",
    "Держатель карты IVAN PETROV, карта 4111 1111 1111 1111, CVV 123.",
    "Место рождения клиента Казань, гражданство Россия, телефон +7 903 222-11-00.",
]

def pct(xs, p):
    if not xs:
        return None
    ys=sorted(xs)
    return ys[min(int(len(ys)*p), len(ys)-1)]

async def run_level(client, url, target_rps, duration_s, max_inflight):
    sem=asyncio.Semaphore(max_inflight)
    statuses=Counter()
    lat=[]
    started=0
    prefix=f"s3-{target_rps}-{uuid.uuid4().hex[:8]}"
    t0=time.perf_counter()
    tasks=[]

    async def one(i):
        nonlocal started
        async with sem:
            payload=PAYLOADS[i % len(PAYLOADS)]
            pid=f"{prefix}-{i}"
            ts=time.perf_counter()
            try:
                r=await client.post(url+"/process", json={"payload":payload,"payload_id":pid})
                statuses[str(r.status_code)] += 1
            except Exception as e:
                statuses[type(e).__name__] += 1
            finally:
                lat.append(time.perf_counter()-ts)

    # 20 scheduling slices per second keeps timing stable without creating one task per micro-interval.
    slices=int(duration_s*20)
    per_slice=target_rps/20.0
    carry=0.0
    idx=0
    for s in range(slices):
        due=per_slice+carry
        n=int(due)
        carry=due-n
        for _ in range(n):
            tasks.append(asyncio.create_task(one(idx)))
            idx+=1
        started+=n
        target_time=t0+(s+1)/20.0
        await asyncio.sleep(max(0, target_time-time.perf_counter()))

    await asyncio.gather(*tasks)
    wall=time.perf_counter()-t0
    completed=sum(statuses.values())
    ok=statuses.get("200",0)
    result={
        "target_rps":target_rps,
        "duration_s":duration_s,
        "offered_requests":started,
        "completed":completed,
        "ok_200":ok,
        "statuses":dict(statuses),
        "wall_s":round(wall,3),
        "achieved_200_rps":round(ok/wall,1),
        "completed_rps":round(completed/wall,1),
        "p50_ms":round(pct(lat,0.50)*1000,1) if lat else None,
        "p95_ms":round(pct(lat,0.95)*1000,1) if lat else None,
        "p99_ms":round(pct(lat,0.99)*1000,1) if lat else None,
        "mean_ms":round(statistics.mean(lat)*1000,1) if lat else None,
    }
    print("RESULT", json.dumps(result, ensure_ascii=False))
    return result

async def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--url", default="http://135.106.220.67")
    ap.add_argument("--duration", type=int, default=8)
    ap.add_argument("--levels", default="250,500,750,1000")
    ap.add_argument("--max-inflight", type=int, default=200)
    args=ap.parse_args()
    limits=httpx.Limits(max_connections=args.max_inflight, max_keepalive_connections=args.max_inflight)
    timeout=httpx.Timeout(10.0, connect=5.0)
    async with httpx.AsyncClient(timeout=timeout, limits=limits) as client:
        # warm-up
        await client.get(args.url+"/ready")
        results=[]
        for lvl in [int(x) for x in args.levels.split(",")]:
            print(f"=== TARGET {lvl} RPS ===")
            results.append(await run_level(client,args.url,lvl,args.duration,args.max_inflight))
            await asyncio.sleep(2)
    with open("stage3_load_ramp.json","w",encoding="utf-8") as f:
        json.dump(results,f,ensure_ascii=False,indent=2)

if __name__=="__main__":
    asyncio.run(main())
