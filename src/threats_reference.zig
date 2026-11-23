//! TEST ONLY: the lifted threat evaluators and attacker routines as generated before the
//! speed pass of 2026-11-18 (tools/port/lift_zig.py at that date: registers and flags kept
//! in the machine through its pointer, every flag computed, the near helpers called
//! recursively). The reference for the differential test in src/threats_test.zig, which
//! compares it with the current src/threats.zig and src/attackers.zig on inputs beyond the
//! recorded ones. Imported only by that test. Do not edit.

const Machine = @import("lifted_machine.zig").Machine;

pub const entry_41b6: u16 = 0x41B6;
pub const entry_4cec: u16 = 0x4CEC;

/// 4793:4162-4C97, from the label `start` until its `retf` (or, for a near
/// helper entered by `call`, its `ret`).
pub fn run41B6(m: *Machine, start: u16) void {
    @setEvalBranchQuota(1_000_000);
    sw: switch (start) {
        0x4162 => {
            m.push(m.di); // 4162 push di
            m.push(m.si); // 4163 push si
            m.di = m.si; // 4164 mov di, si
            m.di = m.add(u16, m.di, 0x9EF6); // 4166 add di, 0x9ef6
            m.setAl(m.rb(m.si +% 0xA09E)); // 416A mov al, byte ptr [si - 0x5f62]
            m.cbw(); // 416E cbw
            m.si = m.ax; // 416F mov si, ax
            m.setAl(m.rb(m.si +% 0x0490)); // 4171 mov al, byte ptr [si + 0x490]
            m.cbw(); // 4175 cbw
            continue :sw 0x4176; // falls through
        },
        0x4176 => {
            m.di = m.add(u16, m.di, m.ax); // 4176 add di, ax
            m.cmp(u8, m.rb(m.di), 0x0); // 4178 cmp byte ptr [di], 0
            if (m.zf) continue :sw 0x4176; // 417B je 0x4176
            m.setBl(m.rb(m.di)); // 417D mov bl, byte ptr [di]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 417F sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 4181 mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.rb(m.si +% 0x047E), m.bl()); // 4185 test byte ptr [si + 0x47e], bl
            m.si = m.pop(); // 4189 pop si
            m.di = m.pop(); // 418A pop di
            _ = m.pop();
            return; // 418B ret
        },
        0x418C => {
            m.push(m.di); // 418C push di
            m.push(m.si); // 418D push si
            m.di = m.si; // 418E mov di, si
            m.di = m.add(u16, m.di, 0x9EF6); // 4190 add di, 0x9ef6
            m.setAl(m.rb(m.si +% 0xA164)); // 4194 mov al, byte ptr [si - 0x5e9c]
            m.cbw(); // 4198 cbw
            m.si = m.ax; // 4199 mov si, ax
            m.setAl(m.rb(m.si +% 0x0490)); // 419B mov al, byte ptr [si + 0x490]
            m.cbw(); // 419F cbw
            continue :sw 0x41A0; // falls through
        },
        0x41A0 => {
            m.di = m.add(u16, m.di, m.ax); // 41A0 add di, ax
            m.cmp(u8, m.rb(m.di), 0x0); // 41A2 cmp byte ptr [di], 0
            if (m.zf) continue :sw 0x41A0; // 41A5 je 0x41a0
            m.setBl(m.rb(m.di)); // 41A7 mov bl, byte ptr [di]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 41A9 sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 41AB mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.rb(m.si +% 0x047E), m.bl()); // 41AF test byte ptr [si + 0x47e], bl
            m.si = m.pop(); // 41B3 pop si
            m.di = m.pop(); // 41B4 pop di
            _ = m.pop();
            return; // 41B5 ret
        },
        0x41B6 => {
            m.push(m.bp); // 41B6 push bp
            m.bp = m.sp; // 41B7 mov bp, sp
            m.sp = m.sub(u16, m.sp, 0x1C); // 41B9 sub sp, 0x1c
            m.push(m.di); // 41BC push di
            m.push(m.si); // 41BD push si
            m.push(m.bx); // 41BE push bx
            m.push(m.cx); // 41BF push cx
            m.push(m.dx); // 41C0 push dx
            m.si = m.rw(m.bp +% 0x0006); // 41C1 mov si, word ptr [bp + 6]
            m.setAl(m.rb(m.si +% 0x9EF6)); // 41C4 mov al, byte ptr [si - 0x610a]
            m.cbw(); // 41C8 cbw
            m.bx = m.ax; // 41C9 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x1A71)); // 41CB mov al, byte ptr [bx + 0x1a71]
            m.wb(0x70E5, m.al()); // 41CF mov byte ptr [0x70e5], al
            m.cmp(u8, m.rb(m.bp +% 0x0008), m.al()); // 41D2 cmp byte ptr [bp + 8], al
            if (m.sf == m.of) continue :sw 0x41E6; // 41D5 jge 0x41e6
            m.setAl(m.rb(m.bp +% 0x0008)); // 41D7 mov al, byte ptr [bp + 8]
            m.cbw(); // 41DA cbw
            m.cx = m.ax; // 41DB mov cx, ax
            m.setAl(m.rb(0x70E5)); // 41DD mov al, byte ptr [0x70e5]
            m.cbw(); // 41E0 cbw
            m.ax = m.sub(u16, m.ax, m.cx); // 41E1 sub ax, cx
            continue :sw 0x4C8C; // 41E3 jmp 0x4c8c
        },
        0x41E6 => {
            m.dx = 0x9FEC; // 41E6 mov dx, 0x9fec
            m.bx = m.dx; // 41E9 mov bx, dx
            m.dx = m.inc(u16, m.dx); // 41EB inc dx
            m.setAl(m.rb(m.bp +% 0x0008)); // 41EC mov al, byte ptr [bp + 8]
            m.wb(m.bx, m.al()); // 41EF mov byte ptr [bx], al
            m.cx = 0xA060; // 41F1 mov cx, 0xa060
            m.setAl(m.sub(u8, m.al(), m.al())); // 41F4 sub al, al
            m.wb(0xA060, m.al()); // 41F6 mov byte ptr [0xa060], al
            m.wb(m.bp +% 0xFFFA, m.al()); // 41F9 mov byte ptr [bp - 6], al
            m.wb(m.bp +% 0xFFF4, m.al()); // 41FC mov byte ptr [bp - 0xc], al
            m.cmp(u8, m.rb(m.si +% 0xA51C), 0x0); // 41FF cmp byte ptr [si - 0x5ae4], 0
            if (!m.zf) continue :sw 0x420A; // 4204 jne 0x420a
            continue :sw 0x42A2; // 4206 jmp 0x42a2
        },
        0x420A => {
            m.cmp(u8, m.rb(m.si +% 0x9EED), 0x1); // 420A cmp byte ptr [si - 0x6113], 1
            if (!m.zf) continue :sw 0x4256; // 420F jne 0x4256
            m.cmp(u8, m.rb(m.si +% 0xA095), 0x0); // 4211 cmp byte ptr [si - 0x5f6b], 0
            if (m.zf) continue :sw 0x4250; // 4216 je 0x4250
            m.di = m.si; // 4218 mov di, si
            m.di = m.sub(u16, m.di, 0x9); // 421A sub di, 9
            m.setAl(m.rb(m.di +% 0xA09E)); // 421D mov al, byte ptr [di - 0x5f62]
            m.cbw(); // 4221 cbw
            m.bx = m.ax; // 4222 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // 4224 mov al, byte ptr [bx + 0x490]
            m.cbw(); // 4228 cbw
            m.cmp(u16, m.ax, 0x9); // 4229 cmp ax, 9
            if (m.zf) continue :sw 0x4250; // 422C je 0x4250
            continue :sw 0x422E; // falls through
        },
        0x422E => {
            m.di = m.add(u16, m.di, m.ax); // 422E add di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // 4230 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0x422E; // 4235 je 0x422e
            m.setAl(m.rb(m.bx +% 0x047E)); // 4237 mov al, byte ptr [bx + 0x47e]
            m.setBl(m.rb(m.di +% 0x9EF6)); // 423B mov bl, byte ptr [di - 0x610a]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 423F sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 4241 mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.bl(), m.al()); // 4245 test bl, al
            if (m.zf) continue :sw 0x4250; // 4247 je 0x4250
            m.wb(m.bp +% 0xFFF4, 0x1); // 4249 mov byte ptr [bp - 0xc], 1
            continue :sw 0x4256; // 424D jmp 0x4256
        },
        0x4250 => {
            m.bx = m.dx; // 4250 mov bx, dx
            m.dx = m.inc(u16, m.dx); // 4252 inc dx
            m.wb(m.bx, 0x3); // 4253 mov byte ptr [bx], 3
            continue :sw 0x4256; // falls through
        },
        0x4256 => {
            m.cmp(u8, m.rb(m.si +% 0x9EEB), 0x1); // 4256 cmp byte ptr [si - 0x6115], 1
            if (!m.zf) continue :sw 0x42A2; // 425B jne 0x42a2
            m.cmp(u8, m.rb(m.si +% 0xA093), 0x0); // 425D cmp byte ptr [si - 0x5f6d], 0
            if (m.zf) continue :sw 0x429C; // 4262 je 0x429c
            m.di = m.si; // 4264 mov di, si
            m.di = m.sub(u16, m.di, 0xB); // 4266 sub di, 0xb
            m.setAl(m.rb(m.di +% 0xA09E)); // 4269 mov al, byte ptr [di - 0x5f62]
            m.cbw(); // 426D cbw
            m.bx = m.ax; // 426E mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // 4270 mov al, byte ptr [bx + 0x490]
            m.cbw(); // 4274 cbw
            m.cmp(u16, m.ax, 0xB); // 4275 cmp ax, 0xb
            if (m.zf) continue :sw 0x429C; // 4278 je 0x429c
            continue :sw 0x427A; // falls through
        },
        0x427A => {
            m.di = m.add(u16, m.di, m.ax); // 427A add di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // 427C cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0x427A; // 4281 je 0x427a
            m.setAl(m.rb(m.bx +% 0x047E)); // 4283 mov al, byte ptr [bx + 0x47e]
            m.setBl(m.rb(m.di +% 0x9EF6)); // 4287 mov bl, byte ptr [di - 0x610a]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 428B sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 428D mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.bl(), m.al()); // 4291 test bl, al
            if (m.zf) continue :sw 0x429C; // 4293 je 0x429c
            m.wb(m.bp +% 0xFFF4, 0x1); // 4295 mov byte ptr [bp - 0xc], 1
            continue :sw 0x42A2; // 4299 jmp 0x42a2
        },
        0x429C => {
            m.bx = m.dx; // 429C mov bx, dx
            m.dx = m.inc(u16, m.dx); // 429E inc dx
            m.wb(m.bx, 0x3); // 429F mov byte ptr [bx], 3
            continue :sw 0x42A2; // falls through
        },
        0x42A2 => {
            m.setAl(m.rb(0xA03A)); // 42A2 mov al, byte ptr [0xa03a]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // 42A5 sub ah, ah
            m.di = m.ax; // 42A7 mov di, ax
            m.bx = m.si; // 42A9 mov bx, si
            m.bx = m.sub(u16, m.bx, m.di); // 42AB sub bx, di
            m.cmp(u8, m.rb(m.bx +% 0x0A68), m.ah()); // 42AD cmp byte ptr [bx + 0xa68], ah
            if (m.zf) continue :sw 0x42F0; // 42B1 je 0x42f0
            m.cmp(u8, m.rb(m.di +% 0xA09E), m.ah()); // 42B3 cmp byte ptr [di - 0x5f62], ah
            if (m.zf) continue :sw 0x42EA; // 42B7 je 0x42ea
            m.setAl(m.rb(m.di +% 0xA09E)); // 42B9 mov al, byte ptr [di - 0x5f62]
            m.cbw(); // 42BD cbw
            m.si = m.ax; // 42BE mov si, ax
            m.setAl(m.rb(m.si +% 0x0490)); // 42C0 mov al, byte ptr [si + 0x490]
            m.cbw(); // 42C4 cbw
            continue :sw 0x42C5; // falls through
        },
        0x42C5 => {
            m.di = m.add(u16, m.di, m.ax); // 42C5 add di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // 42C7 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0x42C5; // 42CC je 0x42c5
            m.setAl(m.rb(m.si +% 0x047E)); // 42CE mov al, byte ptr [si + 0x47e]
            m.si = m.rw(m.bp +% 0x0006); // 42D2 mov si, word ptr [bp + 6]
            m.setBl(m.rb(m.di +% 0x9EF6)); // 42D5 mov bl, byte ptr [di - 0x610a]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 42D9 sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 42DB mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.bl(), m.al()); // 42DF test bl, al
            if (m.zf) continue :sw 0x42EA; // 42E1 je 0x42ea
            m.wb(m.bp +% 0xFFF4, 0x1); // 42E3 mov byte ptr [bp - 0xc], 1
            continue :sw 0x42F0; // 42E7 jmp 0x42f0
        },
        0x42EA => {
            m.bx = m.dx; // 42EA mov bx, dx
            m.dx = m.inc(u16, m.dx); // 42EC inc dx
            m.wb(m.bx, 0x9); // 42ED mov byte ptr [bx], 9
            continue :sw 0x42F0; // falls through
        },
        0x42F0 => {
            m.setAl(m.rb(0xA03B)); // 42F0 mov al, byte ptr [0xa03b]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // 42F3 sub ah, ah
            m.di = m.ax; // 42F5 mov di, ax
            m.bx = m.si; // 42F7 mov bx, si
            m.bx = m.sub(u16, m.bx, m.di); // 42F9 sub bx, di
            m.cmp(u8, m.rb(m.bx +% 0x0A68), m.ah()); // 42FB cmp byte ptr [bx + 0xa68], ah
            if (m.zf) continue :sw 0x433E; // 42FF je 0x433e
            m.cmp(u8, m.rb(m.di +% 0xA09E), m.ah()); // 4301 cmp byte ptr [di - 0x5f62], ah
            if (m.zf) continue :sw 0x4338; // 4305 je 0x4338
            m.setAl(m.rb(m.di +% 0xA09E)); // 4307 mov al, byte ptr [di - 0x5f62]
            m.cbw(); // 430B cbw
            m.si = m.ax; // 430C mov si, ax
            m.setAl(m.rb(m.si +% 0x0490)); // 430E mov al, byte ptr [si + 0x490]
            m.cbw(); // 4312 cbw
            continue :sw 0x4313; // falls through
        },
        0x4313 => {
            m.di = m.add(u16, m.di, m.ax); // 4313 add di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // 4315 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0x4313; // 431A je 0x4313
            m.setAl(m.rb(m.si +% 0x047E)); // 431C mov al, byte ptr [si + 0x47e]
            m.si = m.rw(m.bp +% 0x0006); // 4320 mov si, word ptr [bp + 6]
            m.setBl(m.rb(m.di +% 0x9EF6)); // 4323 mov bl, byte ptr [di - 0x610a]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 4327 sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 4329 mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.bl(), m.al()); // 432D test bl, al
            if (m.zf) continue :sw 0x4338; // 432F je 0x4338
            m.wb(m.bp +% 0xFFF4, 0x1); // 4331 mov byte ptr [bp - 0xc], 1
            continue :sw 0x433E; // 4335 jmp 0x433e
        },
        0x4338 => {
            m.bx = m.dx; // 4338 mov bx, dx
            m.dx = m.inc(u16, m.dx); // 433A inc dx
            m.wb(m.bx, 0x9); // 433B mov byte ptr [bx], 9
            continue :sw 0x433E; // falls through
        },
        0x433E => {
            m.cmp(u8, m.rb(m.si +% 0x37DA), 0x0); // 433E cmp byte ptr [si + 0x37da], 0
            if (!m.zf) continue :sw 0x4348; // 4343 jne 0x4348
            continue :sw 0x43E0; // 4345 jmp 0x43e0
        },
        0x4348 => {
            m.cmp(u8, m.rb(m.si +% 0x9EFF), 0x8); // 4348 cmp byte ptr [si - 0x6101], 8
            if (!m.zf) continue :sw 0x4394; // 434D jne 0x4394
            m.cmp(u8, m.rb(m.si +% 0xA16D), 0x0); // 434F cmp byte ptr [si - 0x5e93], 0
            if (m.zf) continue :sw 0x438E; // 4354 je 0x438e
            m.di = m.si; // 4356 mov di, si
            m.di = m.add(u16, m.di, 0x9); // 4358 add di, 9
            m.setAl(m.rb(m.di +% 0xA164)); // 435B mov al, byte ptr [di - 0x5e9c]
            m.cbw(); // 435F cbw
            m.bx = m.ax; // 4360 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // 4362 mov al, byte ptr [bx + 0x490]
            m.cbw(); // 4366 cbw
            m.cmp(u16, m.ax, 0xFFF7); // 4367 cmp ax, 0xfff7
            if (m.zf) continue :sw 0x438E; // 436A je 0x438e
            continue :sw 0x436C; // falls through
        },
        0x436C => {
            m.di = m.add(u16, m.di, m.ax); // 436C add di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // 436E cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0x436C; // 4373 je 0x436c
            m.setAl(m.rb(m.bx +% 0x047E)); // 4375 mov al, byte ptr [bx + 0x47e]
            m.setBl(m.rb(m.di +% 0x9EF6)); // 4379 mov bl, byte ptr [di - 0x610a]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 437D sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 437F mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.bl(), m.al()); // 4383 test bl, al
            if (m.zf) continue :sw 0x438E; // 4385 je 0x438e
            m.wb(m.bp +% 0xFFFA, 0x1); // 4387 mov byte ptr [bp - 6], 1
            continue :sw 0x4394; // 438B jmp 0x4394
        },
        0x438E => {
            m.bx = m.cx; // 438E mov bx, cx
            m.cx = m.inc(u16, m.cx); // 4390 inc cx
            m.wb(m.bx, 0x3); // 4391 mov byte ptr [bx], 3
            continue :sw 0x4394; // falls through
        },
        0x4394 => {
            m.cmp(u8, m.rb(m.si +% 0x9F01), 0x8); // 4394 cmp byte ptr [si - 0x60ff], 8
            if (!m.zf) continue :sw 0x43E0; // 4399 jne 0x43e0
            m.cmp(u8, m.rb(m.si +% 0xA16F), 0x0); // 439B cmp byte ptr [si - 0x5e91], 0
            if (m.zf) continue :sw 0x43DA; // 43A0 je 0x43da
            m.di = m.si; // 43A2 mov di, si
            m.di = m.add(u16, m.di, 0xB); // 43A4 add di, 0xb
            m.setAl(m.rb(m.di +% 0xA164)); // 43A7 mov al, byte ptr [di - 0x5e9c]
            m.cbw(); // 43AB cbw
            m.bx = m.ax; // 43AC mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // 43AE mov al, byte ptr [bx + 0x490]
            m.cbw(); // 43B2 cbw
            m.cmp(u16, m.ax, 0xFFF5); // 43B3 cmp ax, 0xfff5
            if (m.zf) continue :sw 0x43DA; // 43B6 je 0x43da
            continue :sw 0x43B8; // falls through
        },
        0x43B8 => {
            m.di = m.add(u16, m.di, m.ax); // 43B8 add di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // 43BA cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0x43B8; // 43BF je 0x43b8
            m.setAl(m.rb(m.bx +% 0x047E)); // 43C1 mov al, byte ptr [bx + 0x47e]
            m.setBl(m.rb(m.di +% 0x9EF6)); // 43C5 mov bl, byte ptr [di - 0x610a]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 43C9 sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 43CB mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.bl(), m.al()); // 43CF test bl, al
            if (m.zf) continue :sw 0x43DA; // 43D1 je 0x43da
            m.wb(m.bp +% 0xFFFA, 0x1); // 43D3 mov byte ptr [bp - 6], 1
            continue :sw 0x43E0; // 43D7 jmp 0x43e0
        },
        0x43DA => {
            m.bx = m.cx; // 43DA mov bx, cx
            m.cx = m.inc(u16, m.cx); // 43DC inc cx
            m.wb(m.bx, 0x3); // 43DD mov byte ptr [bx], 3
            continue :sw 0x43E0; // falls through
        },
        0x43E0 => {
            m.setAl(m.rb(0xA04A)); // 43E0 mov al, byte ptr [0xa04a]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // 43E3 sub ah, ah
            m.di = m.ax; // 43E5 mov di, ax
            m.bx = m.si; // 43E7 mov bx, si
            m.bx = m.sub(u16, m.bx, m.di); // 43E9 sub bx, di
            m.cmp(u8, m.rb(m.bx +% 0x0A68), m.ah()); // 43EB cmp byte ptr [bx + 0xa68], ah
            if (m.zf) continue :sw 0x442E; // 43EF je 0x442e
            m.cmp(u8, m.rb(m.di +% 0xA164), m.ah()); // 43F1 cmp byte ptr [di - 0x5e9c], ah
            if (m.zf) continue :sw 0x4428; // 43F5 je 0x4428
            m.setAl(m.rb(m.di +% 0xA164)); // 43F7 mov al, byte ptr [di - 0x5e9c]
            m.cbw(); // 43FB cbw
            m.si = m.ax; // 43FC mov si, ax
            m.setAl(m.rb(m.si +% 0x0490)); // 43FE mov al, byte ptr [si + 0x490]
            m.cbw(); // 4402 cbw
            continue :sw 0x4403; // falls through
        },
        0x4403 => {
            m.di = m.add(u16, m.di, m.ax); // 4403 add di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // 4405 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0x4403; // 440A je 0x4403
            m.setAl(m.rb(m.si +% 0x047E)); // 440C mov al, byte ptr [si + 0x47e]
            m.si = m.rw(m.bp +% 0x0006); // 4410 mov si, word ptr [bp + 6]
            m.setBl(m.rb(m.di +% 0x9EF6)); // 4413 mov bl, byte ptr [di - 0x610a]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 4417 sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 4419 mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.bl(), m.al()); // 441D test bl, al
            if (m.zf) continue :sw 0x4428; // 441F je 0x4428
            m.wb(m.bp +% 0xFFFA, 0x1); // 4421 mov byte ptr [bp - 6], 1
            continue :sw 0x442E; // 4425 jmp 0x442e
        },
        0x4428 => {
            m.bx = m.cx; // 4428 mov bx, cx
            m.cx = m.inc(u16, m.cx); // 442A inc cx
            m.wb(m.bx, 0x9); // 442B mov byte ptr [bx], 9
            continue :sw 0x442E; // falls through
        },
        0x442E => {
            m.setAl(m.rb(0xA04B)); // 442E mov al, byte ptr [0xa04b]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // 4431 sub ah, ah
            m.di = m.ax; // 4433 mov di, ax
            m.bx = m.si; // 4435 mov bx, si
            m.bx = m.sub(u16, m.bx, m.di); // 4437 sub bx, di
            m.cmp(u8, m.rb(m.bx +% 0x0A68), m.ah()); // 4439 cmp byte ptr [bx + 0xa68], ah
            if (m.zf) continue :sw 0x447C; // 443D je 0x447c
            m.cmp(u8, m.rb(m.di +% 0xA164), m.ah()); // 443F cmp byte ptr [di - 0x5e9c], ah
            if (m.zf) continue :sw 0x4476; // 4443 je 0x4476
            m.setAl(m.rb(m.di +% 0xA164)); // 4445 mov al, byte ptr [di - 0x5e9c]
            m.cbw(); // 4449 cbw
            m.si = m.ax; // 444A mov si, ax
            m.setAl(m.rb(m.si +% 0x0490)); // 444C mov al, byte ptr [si + 0x490]
            m.cbw(); // 4450 cbw
            continue :sw 0x4451; // falls through
        },
        0x4451 => {
            m.di = m.add(u16, m.di, m.ax); // 4451 add di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // 4453 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0x4451; // 4458 je 0x4451
            m.setAl(m.rb(m.si +% 0x047E)); // 445A mov al, byte ptr [si + 0x47e]
            m.si = m.rw(m.bp +% 0x0006); // 445E mov si, word ptr [bp + 6]
            m.setBl(m.rb(m.di +% 0x9EF6)); // 4461 mov bl, byte ptr [di - 0x610a]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 4465 sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 4467 mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.bl(), m.al()); // 446B test bl, al
            if (m.zf) continue :sw 0x4476; // 446D je 0x4476
            m.wb(m.bp +% 0xFFFA, 0x1); // 446F mov byte ptr [bp - 6], 1
            continue :sw 0x447C; // 4473 jmp 0x447c
        },
        0x4476 => {
            m.bx = m.cx; // 4476 mov bx, cx
            m.cx = m.inc(u16, m.cx); // 4478 inc cx
            m.wb(m.bx, 0x9); // 4479 mov byte ptr [bx], 9
            continue :sw 0x447C; // falls through
        },
        0x447C => {
            m.setAl(m.sub(u8, m.al(), m.al())); // 447C sub al, al
            m.wb(m.bp +% 0xFFEE, m.al()); // 447E mov byte ptr [bp - 0x12], al
            m.wb(m.bp +% 0xFFFC, m.al()); // 4481 mov byte ptr [bp - 4], al
            m.wb(m.bp +% 0xFFF6, m.al()); // 4484 mov byte ptr [bp - 0xa], al
            m.wb(m.bp +% 0xFFFE, m.al()); // 4487 mov byte ptr [bp - 2], al
            m.wb(m.bp +% 0xFFF2, m.al()); // 448A mov byte ptr [bp - 0xe], al
            m.di = 0x9; // 448D mov di, 9
            continue :sw 0x4490; // falls through
        },
        0x4490 => {
            m.si = m.add(u16, m.si, m.di); // 4490 add si, di
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x8); // 4492 cmp byte ptr [si - 0x610a], 8
            if (!m.zf) continue :sw 0x44A6; // 4497 jne 0x44a6
            m.cmp(u8, m.rb(0xA060), 0x3); // 4499 cmp byte ptr [0xa060], 3
            if (m.zf) continue :sw 0x44A4; // 449E je 0x44a4
            continue :sw 0x4520; // 44A0 jmp 0x4520
        },
        0x44A4 => {
            m.si = m.add(u16, m.si, m.di); // 44A4 add si, di
            continue :sw 0x44A6; // falls through
        },
        0x44A6 => {
            m.setAl(m.rb(m.si +% 0x9EF6)); // 44A6 mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 44AA or al, al
            if (m.zf) continue :sw 0x44A4; // 44AC je 0x44a4
            m.cmp(u8, m.al(), 0x7); // 44AE cmp al, 7
            if (m.zf) continue :sw 0x4520; // 44B0 je 0x4520
            m.cmp(u8, m.al(), 0x3); // 44B2 cmp al, 3
            if (m.zf) continue :sw 0x44C6; // 44B4 je 0x44c6
            m.cmp(u8, m.al(), 0x5); // 44B6 cmp al, 5
            if (m.zf) continue :sw 0x44C2; // 44B8 je 0x44c2
            m.cmp(u8, m.al(), 0xA); // 44BA cmp al, 0xa
            if (m.zf) continue :sw 0x4500; // 44BC je 0x4500
            continue :sw 0x4710; // 44BE jmp 0x4710
        },
        0x44C2 => {
            continue :sw 0x459E; // 44C2 jmp 0x459e
        },
        0x44C6 => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 44C6 cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x44E4; // 44CB je 0x44e4
            m.push(0x44D0);
            run41B6(m, 0x4162); // 44CD call 0x4162
            if (m.zf) continue :sw 0x44E4; // 44D0 je 0x44e4
            m.cmp(u16, m.ax, m.di); // 44D2 cmp ax, di
            if (m.zf) continue :sw 0x44E4; // 44D4 je 0x44e4
            m.ax = m.neg(u16, m.ax); // 44D6 neg ax
            m.cmp(u16, m.ax, m.di); // 44D8 cmp ax, di
            if (m.zf) continue :sw 0x44E4; // 44DA je 0x44e4
            m.wb(m.bp +% 0xFFF4, 0x1); // 44DC mov byte ptr [bp - 0xc], 1
            continue :sw 0x4520; // 44E0 jmp 0x4520
        },
        0x44E4 => {
            m.bx = m.dx; // 44E4 mov bx, dx
            m.dx = m.inc(u16, m.dx); // 44E6 inc dx
            m.wb(m.bx, 0x9); // 44E7 mov byte ptr [bx], 9
            continue :sw 0x44EA; // falls through
        },
        0x44EA => {
            m.si = m.add(u16, m.si, m.di); // 44EA add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 44EC mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 44F0 or al, al
            if (m.zf) continue :sw 0x44EA; // 44F2 je 0x44ea
            m.cmp(u8, m.al(), 0x5); // 44F4 cmp al, 5
            if (m.zf) continue :sw 0x44FC; // 44F6 je 0x44fc
            continue :sw 0x4520; // 44F8 jmp 0x4520
        },
        0x44FC => {
            continue :sw 0x459E; // 44FC jmp 0x459e
        },
        0x4500 => {
            m.cmp(u8, m.rb(m.bp +% 0xFFF2), 0x1); // 4500 cmp byte ptr [bp - 0xe], 1
            if (m.zf) continue :sw 0x4520; // 4504 je 0x4520
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 4506 cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x4532; // 450B je 0x4532
            m.push(0x4510);
            run41B6(m, 0x418C); // 450D call 0x418c
            if (m.zf) continue :sw 0x4532; // 4510 je 0x4532
            m.cmp(u16, m.ax, m.di); // 4512 cmp ax, di
            if (m.zf) continue :sw 0x4532; // 4514 je 0x4532
            m.ax = m.neg(u16, m.ax); // 4516 neg ax
            m.cmp(u16, m.ax, m.di); // 4518 cmp ax, di
            if (m.zf) continue :sw 0x4532; // 451A je 0x4532
            m.wb(m.bp +% 0xFFFA, 0x1); // 451C mov byte ptr [bp - 6], 1
            continue :sw 0x4520; // falls through
        },
        0x4520 => {
            m.cmp(u16, m.di, 0x9); // 4520 cmp di, 9
            if (m.zf) continue :sw 0x4528; // 4523 je 0x4528
            continue :sw 0x47C4; // 4525 jmp 0x47c4
        },
        0x4528 => {
            m.di = 0xB; // 4528 mov di, 0xb
            m.si = m.rw(m.bp +% 0x0006); // 452B mov si, word ptr [bp + 6]
            continue :sw 0x4490; // 452E jmp 0x4490
        },
        0x4532 => {
            m.bx = m.cx; // 4532 mov bx, cx
            m.cx = m.inc(u16, m.cx); // 4534 inc cx
            m.wb(m.bx, 0x9); // 4535 mov byte ptr [bx], 9
            continue :sw 0x4538; // falls through
        },
        0x4538 => {
            m.si = m.add(u16, m.si, m.di); // 4538 add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 453A mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 453E or al, al
            if (m.zf) continue :sw 0x4538; // 4540 je 0x4538
            m.cmp(u8, m.al(), 0x3); // 4542 cmp al, 3
            if (m.zf) continue :sw 0x454E; // 4544 je 0x454e
            m.cmp(u8, m.al(), 0x5); // 4546 cmp al, 5
            if (m.zf) continue :sw 0x459E; // 4548 je 0x459e
            continue :sw 0x4710; // 454A jmp 0x4710
        },
        0x454E => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 454E cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x456A; // 4553 je 0x456a
            m.push(0x4558);
            run41B6(m, 0x4162); // 4555 call 0x4162
            if (m.zf) continue :sw 0x456A; // 4558 je 0x456a
            m.cmp(u16, m.ax, m.di); // 455A cmp ax, di
            if (m.zf) continue :sw 0x456A; // 455C je 0x456a
            m.ax = m.neg(u16, m.ax); // 455E neg ax
            m.cmp(u16, m.ax, m.di); // 4560 cmp ax, di
            if (m.zf) continue :sw 0x456A; // 4562 je 0x456a
            m.wb(m.bp +% 0xFFF4, 0x1); // 4564 mov byte ptr [bp - 0xc], 1
            continue :sw 0x4520; // 4568 jmp 0x4520
        },
        0x456A => {
            m.bx = m.dx; // 456A mov bx, dx
            m.dx = m.inc(u16, m.dx); // 456C inc dx
            m.wb(m.bx, 0x9); // 456D mov byte ptr [bx], 9
            continue :sw 0x44A4; // 4570 jmp 0x44a4
        },
        0x4574 => {
            m.wb(m.bp +% 0xFFFE, m.inc(u8, m.rb(m.bp +% 0xFFFE))); // 4574 inc byte ptr [bp - 2]
            continue :sw 0x45C0; // 4577 jmp 0x45c0
        },
        0x459E => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 459E cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x45BC; // 45A3 je 0x45bc
            m.push(0x45A8);
            run41B6(m, 0x4162); // 45A5 call 0x4162
            if (m.zf) continue :sw 0x45BC; // 45A8 je 0x45bc
            m.cmp(u16, m.ax, m.di); // 45AA cmp ax, di
            if (m.zf) continue :sw 0x45BC; // 45AC je 0x45bc
            m.ax = m.neg(u16, m.ax); // 45AE neg ax
            m.cmp(u16, m.ax, m.di); // 45B0 cmp ax, di
            if (m.zf) continue :sw 0x45BC; // 45B2 je 0x45bc
            m.wb(m.bp +% 0xFFF4, 0x1); // 45B4 mov byte ptr [bp - 0xc], 1
            continue :sw 0x4520; // 45B8 jmp 0x4520
        },
        0x45BC => {
            m.wb(m.bp +% 0xFFFE, m.add(u8, m.rb(m.bp +% 0xFFFE), 0x10)); // 45BC add byte ptr [bp - 2], 0x10
            continue :sw 0x45C0; // falls through
        },
        0x45C0 => {
            m.si = m.add(u16, m.si, m.di); // 45C0 add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 45C2 mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 45C6 or al, al
            if (m.zf) continue :sw 0x45C0; // 45C8 je 0x45c0
            m.cmp(u8, m.al(), 0x3); // 45CA cmp al, 3
            if (m.zf) continue :sw 0x4574; // 45CC je 0x4574
            m.cmp(u8, m.al(), 0x5); // 45CE cmp al, 5
            if (m.zf) continue :sw 0x459E; // 45D0 je 0x459e
            continue :sw 0x4520; // 45D2 jmp 0x4520
        },
        0x4684 => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 4684 cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x46A2; // 4689 je 0x46a2
            m.push(0x468E);
            run41B6(m, 0x418C); // 468B call 0x418c
            if (m.zf) continue :sw 0x46A2; // 468E je 0x46a2
            m.cmp(u16, m.ax, m.di); // 4690 cmp ax, di
            if (m.zf) continue :sw 0x46A2; // 4692 je 0x46a2
            m.ax = m.neg(u16, m.ax); // 4694 neg ax
            m.cmp(u16, m.ax, m.di); // 4696 cmp ax, di
            if (m.zf) continue :sw 0x46A2; // 4698 je 0x46a2
            m.wb(m.bp +% 0xFFFA, 0x1); // 469A mov byte ptr [bp - 6], 1
            continue :sw 0x4520; // 469E jmp 0x4520
        },
        0x46A2 => {
            m.wb(m.bp +% 0xFFF6, m.inc(u8, m.rb(m.bp +% 0xFFF6))); // 46A2 inc byte ptr [bp - 0xa]
            continue :sw 0x46F6; // 46A5 jmp 0x46f6
        },
        0x46A8 => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 46A8 cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x46C6; // 46AD je 0x46c6
            m.push(0x46B2);
            run41B6(m, 0x4162); // 46AF call 0x4162
            if (m.zf) continue :sw 0x46C6; // 46B2 je 0x46c6
            m.cmp(u16, m.ax, m.di); // 46B4 cmp ax, di
            if (m.zf) continue :sw 0x46C6; // 46B6 je 0x46c6
            m.ax = m.neg(u16, m.ax); // 46B8 neg ax
            m.cmp(u16, m.ax, m.di); // 46BA cmp ax, di
            if (m.zf) continue :sw 0x46C6; // 46BC je 0x46c6
            m.wb(m.bp +% 0xFFF4, 0x1); // 46BE mov byte ptr [bp - 0xc], 1
            continue :sw 0x4520; // 46C2 jmp 0x4520
        },
        0x46C6 => {
            m.bx = m.dx; // 46C6 mov bx, dx
            m.dx = m.inc(u16, m.dx); // 46C8 inc dx
            m.wb(m.bx, 0x9); // 46C9 mov byte ptr [bx], 9
            continue :sw 0x46F6; // 46CC jmp 0x46f6
        },
        0x46CE => {
            m.cmp(u8, m.rb(m.bp +% 0xFFF2), 0x1); // 46CE cmp byte ptr [bp - 0xe], 1
            if (m.zf) continue :sw 0x46EE; // 46D2 je 0x46ee
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 46D4 cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x46F2; // 46D9 je 0x46f2
            m.push(0x46DE);
            run41B6(m, 0x418C); // 46DB call 0x418c
            if (m.zf) continue :sw 0x46F2; // 46DE je 0x46f2
            m.cmp(u16, m.ax, m.di); // 46E0 cmp ax, di
            if (m.zf) continue :sw 0x46F2; // 46E2 je 0x46f2
            m.ax = m.neg(u16, m.ax); // 46E4 neg ax
            m.cmp(u16, m.ax, m.di); // 46E6 cmp ax, di
            if (m.zf) continue :sw 0x46F2; // 46E8 je 0x46f2
            m.wb(m.bp +% 0xFFFA, 0x1); // 46EA mov byte ptr [bp - 6], 1
            continue :sw 0x46EE; // falls through
        },
        0x46EE => {
            continue :sw 0x4520; // 46EE jmp 0x4520
        },
        0x46F2 => {
            m.wb(m.bp +% 0xFFF6, m.add(u8, m.rb(m.bp +% 0xFFF6), 0x10)); // 46F2 add byte ptr [bp - 0xa], 0x10
            continue :sw 0x46F6; // falls through
        },
        0x46F6 => {
            m.si = m.add(u16, m.si, m.di); // 46F6 add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 46F8 mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 46FC or al, al
            if (m.zf) continue :sw 0x46F6; // 46FE je 0x46f6
            m.cmp(u8, m.al(), 0x3); // 4700 cmp al, 3
            if (m.zf) continue :sw 0x46A8; // 4702 je 0x46a8
            m.cmp(u8, m.al(), 0x5); // 4704 cmp al, 5
            if (m.zf) continue :sw 0x4760; // 4706 je 0x4760
            m.cmp(u8, m.al(), 0xA); // 4708 cmp al, 0xa
            if (!m.zf) continue :sw 0x4710; // 470A jne 0x4710
            continue :sw 0x4684; // 470C jmp 0x4684
        },
        0x4710 => {
            m.cmp(u8, m.al(), 0xC); // 4710 cmp al, 0xc
            if (m.zf) continue :sw 0x46CE; // 4712 je 0x46ce
            continue :sw 0x4520; // 4714 jmp 0x4520
        },
        0x4718 => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 4718 cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x4736; // 471D je 0x4736
            m.push(0x4722);
            run41B6(m, 0x4162); // 471F call 0x4162
            if (m.zf) continue :sw 0x4736; // 4722 je 0x4736
            m.cmp(u16, m.ax, m.di); // 4724 cmp ax, di
            if (m.zf) continue :sw 0x4736; // 4726 je 0x4736
            m.ax = m.neg(u16, m.ax); // 4728 neg ax
            m.cmp(u16, m.ax, m.di); // 472A cmp ax, di
            if (m.zf) continue :sw 0x4736; // 472C je 0x4736
            m.wb(m.bp +% 0xFFF4, 0x1); // 472E mov byte ptr [bp - 0xc], 1
            continue :sw 0x4520; // 4732 jmp 0x4520
        },
        0x4736 => {
            m.wb(m.bp +% 0xFFFE, m.inc(u8, m.rb(m.bp +% 0xFFFE))); // 4736 inc byte ptr [bp - 2]
            continue :sw 0x4782; // 4739 jmp 0x4782
        },
        0x473C => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 473C cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x475A; // 4741 je 0x475a
            m.push(0x4746);
            run41B6(m, 0x418C); // 4743 call 0x418c
            if (m.zf) continue :sw 0x475A; // 4746 je 0x475a
            m.cmp(u16, m.ax, m.di); // 4748 cmp ax, di
            if (m.zf) continue :sw 0x475A; // 474A je 0x475a
            m.ax = m.neg(u16, m.ax); // 474C neg ax
            m.cmp(u16, m.ax, m.di); // 474E cmp ax, di
            if (m.zf) continue :sw 0x475A; // 4750 je 0x475a
            m.wb(m.bp +% 0xFFFA, 0x1); // 4752 mov byte ptr [bp - 6], 1
            continue :sw 0x4520; // 4756 jmp 0x4520
        },
        0x475A => {
            m.wb(m.bp +% 0xFFF6, m.inc(u8, m.rb(m.bp +% 0xFFF6))); // 475A inc byte ptr [bp - 0xa]
            continue :sw 0x4782; // 475D jmp 0x4782
        },
        0x4760 => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 4760 cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x477E; // 4765 je 0x477e
            m.push(0x476A);
            run41B6(m, 0x4162); // 4767 call 0x4162
            if (m.zf) continue :sw 0x477E; // 476A je 0x477e
            m.cmp(u16, m.ax, m.di); // 476C cmp ax, di
            if (m.zf) continue :sw 0x477E; // 476E je 0x477e
            m.ax = m.neg(u16, m.ax); // 4770 neg ax
            m.cmp(u16, m.ax, m.di); // 4772 cmp ax, di
            if (m.zf) continue :sw 0x477E; // 4774 je 0x477e
            m.wb(m.bp +% 0xFFF4, 0x1); // 4776 mov byte ptr [bp - 0xc], 1
            continue :sw 0x4520; // 477A jmp 0x4520
        },
        0x477E => {
            m.wb(m.bp +% 0xFFFE, m.add(u8, m.rb(m.bp +% 0xFFFE), 0x10)); // 477E add byte ptr [bp - 2], 0x10
            continue :sw 0x4782; // falls through
        },
        0x4782 => {
            m.si = m.add(u16, m.si, m.di); // 4782 add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 4784 mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 4788 or al, al
            if (m.zf) continue :sw 0x4782; // 478A je 0x4782
            m.cmp(u8, m.al(), 0x3); // 478C cmp al, 3
            if (m.zf) continue :sw 0x4718; // 478E je 0x4718
            m.cmp(u8, m.al(), 0x5); // 4790 cmp al, 5
            if (m.zf) continue :sw 0x4760; // 4792 je 0x4760
            m.cmp(u8, m.al(), 0xA); // 4794 cmp al, 0xa
            if (m.zf) continue :sw 0x473C; // 4796 je 0x473c
            m.cmp(u8, m.al(), 0xC); // 4798 cmp al, 0xc
            if (m.zf) continue :sw 0x47A0; // 479A je 0x47a0
            continue :sw 0x4520; // 479C jmp 0x4520
        },
        0x47A0 => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 47A0 cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x47BE; // 47A5 je 0x47be
            m.push(0x47AA);
            run41B6(m, 0x418C); // 47A7 call 0x418c
            if (m.zf) continue :sw 0x47BE; // 47AA je 0x47be
            m.cmp(u16, m.ax, m.di); // 47AC cmp ax, di
            if (m.zf) continue :sw 0x47BE; // 47AE je 0x47be
            m.ax = m.neg(u16, m.ax); // 47B0 neg ax
            m.cmp(u16, m.ax, m.di); // 47B2 cmp ax, di
            if (m.zf) continue :sw 0x47BE; // 47B4 je 0x47be
            m.wb(m.bp +% 0xFFFA, 0x1); // 47B6 mov byte ptr [bp - 6], 1
            continue :sw 0x4520; // 47BA jmp 0x4520
        },
        0x47BE => {
            m.wb(m.bp +% 0xFFF6, m.add(u8, m.rb(m.bp +% 0xFFF6), 0x10)); // 47BE add byte ptr [bp - 0xa], 0x10
            continue :sw 0x4782; // 47C2 jmp 0x4782
        },
        0x47C4 => {
            m.cmp(u16, m.di, 0xB); // 47C4 cmp di, 0xb
            if (!m.zf) continue :sw 0x47D4; // 47C7 jne 0x47d4
            m.di = 0xFFF7; // 47C9 mov di, 0xfff7
            m.si = m.rw(m.bp +% 0x0006); // 47CC mov si, word ptr [bp + 6]
            m.si = m.sub(u16, m.si, 0x9); // 47CF sub si, 9
            continue :sw 0x47E6; // 47D2 jmp 0x47e6
        },
        0x47D4 => {
            m.cmp(u16, m.di, 0xFFF7); // 47D4 cmp di, -9
            if (!m.zf) continue :sw 0x47F8; // 47D7 jne 0x47f8
            m.wb(m.bp +% 0xFFF2, 0x0); // 47D9 mov byte ptr [bp - 0xe], 0
            m.di = 0xFFF5; // 47DD mov di, 0xfff5
            m.si = m.rw(m.bp +% 0x0006); // 47E0 mov si, word ptr [bp + 6]
            m.si = m.sub(u16, m.si, 0xB); // 47E3 sub si, 0xb
            continue :sw 0x47E6; // falls through
        },
        0x47E6 => {
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x1); // 47E6 cmp byte ptr [si - 0x610a], 1
            if (m.zf) continue :sw 0x47F0; // 47EB je 0x47f0
            continue :sw 0x44A6; // 47ED jmp 0x44a6
        },
        0x47F0 => {
            m.wb(m.bp +% 0xFFF2, 0x1); // 47F0 mov byte ptr [bp - 0xe], 1
            continue :sw 0x44A4; // 47F4 jmp 0x44a4
        },
        0x47F8 => {
            m.si = m.rw(m.bp +% 0x0006); // 47F8 mov si, word ptr [bp + 6]
            m.wb(m.bp +% 0xFFEC, 0x3); // 47FB mov byte ptr [bp - 0x14], 3
            continue :sw 0x47FF; // falls through
        },
        0x47FF => {
            m.setBl(m.rb(m.bp +% 0xFFEC)); // 47FF mov bl, byte ptr [bp - 0x14]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 4802 sub bh, bh
            m.setAl(m.rb(m.bx +% 0x04A6)); // 4804 mov al, byte ptr [bx + 0x4a6]
            m.cbw(); // 4808 cbw
            m.di = m.ax; // 4809 mov di, ax
            continue :sw 0x480B; // falls through
        },
        0x480B => {
            m.si = m.add(u16, m.si, m.di); // 480B add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 480D mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 4811 or al, al
            if (m.zf) continue :sw 0x480B; // 4813 je 0x480b
            m.cmp(u8, m.al(), 0x7); // 4815 cmp al, 7
            if (m.zf) continue :sw 0x4880; // 4817 je 0x4880
            m.cmp(u8, m.al(), 0x4); // 4819 cmp al, 4
            if (m.zf) continue :sw 0x482C; // 481B je 0x482c
            m.cmp(u8, m.al(), 0x5); // 481D cmp al, 5
            if (m.zf) continue :sw 0x4828; // 481F je 0x4828
            m.cmp(u8, m.al(), 0xB); // 4821 cmp al, 0xb
            if (m.zf) continue :sw 0x4866; // 4823 je 0x4866
            continue :sw 0x4A8C; // 4825 jmp 0x4a8c
        },
        0x4828 => {
            continue :sw 0x4920; // 4828 jmp 0x4920
        },
        0x482C => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 482C cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x484A; // 4831 je 0x484a
            m.push(0x4836);
            run41B6(m, 0x4162); // 4833 call 0x4162
            if (m.zf) continue :sw 0x484A; // 4836 je 0x484a
            m.cmp(u16, m.ax, m.di); // 4838 cmp ax, di
            if (m.zf) continue :sw 0x484A; // 483A je 0x484a
            m.ax = m.neg(u16, m.ax); // 483C neg ax
            m.cmp(u16, m.ax, m.di); // 483E cmp ax, di
            if (m.zf) continue :sw 0x484A; // 4840 je 0x484a
            m.wb(m.bp +% 0xFFF4, 0x1); // 4842 mov byte ptr [bp - 0xc], 1
            continue :sw 0x4880; // 4846 jmp 0x4880
        },
        0x484A => {
            m.bx = m.dx; // 484A mov bx, dx
            m.dx = m.inc(u16, m.dx); // 484C inc dx
            m.wb(m.bx, 0xF); // 484D mov byte ptr [bx], 0xf
            continue :sw 0x4850; // falls through
        },
        0x4850 => {
            m.si = m.add(u16, m.si, m.di); // 4850 add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 4852 mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 4856 or al, al
            if (m.zf) continue :sw 0x4850; // 4858 je 0x4850
            m.cmp(u8, m.al(), 0x4); // 485A cmp al, 4
            if (m.zf) continue :sw 0x482C; // 485C je 0x482c
            m.cmp(u8, m.al(), 0x5); // 485E cmp al, 5
            if (!m.zf) continue :sw 0x4880; // 4860 jne 0x4880
            continue :sw 0x4920; // 4862 jmp 0x4920
        },
        0x4866 => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 4866 cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x4892; // 486B je 0x4892
            m.push(0x4870);
            run41B6(m, 0x418C); // 486D call 0x418c
            if (m.zf) continue :sw 0x4892; // 4870 je 0x4892
            m.cmp(u16, m.ax, m.di); // 4872 cmp ax, di
            if (m.zf) continue :sw 0x4892; // 4874 je 0x4892
            m.ax = m.neg(u16, m.ax); // 4876 neg ax
            m.cmp(u16, m.ax, m.di); // 4878 cmp ax, di
            if (m.zf) continue :sw 0x4892; // 487A je 0x4892
            m.wb(m.bp +% 0xFFFA, 0x1); // 487C mov byte ptr [bp - 6], 1
            continue :sw 0x4880; // falls through
        },
        0x4880 => {
            m.si = m.rw(m.bp +% 0x0006); // 4880 mov si, word ptr [bp + 6]
            m.cmp(u8, m.rb(m.bp +% 0xFFEC), 0x0); // 4883 cmp byte ptr [bp - 0x14], 0
            if (!m.zf) continue :sw 0x488C; // 4887 jne 0x488c
            continue :sw 0x4B40; // 4889 jmp 0x4b40
        },
        0x488C => {
            m.wb(m.bp +% 0xFFEC, m.dec(u8, m.rb(m.bp +% 0xFFEC))); // 488C dec byte ptr [bp - 0x14]
            continue :sw 0x47FF; // 488F jmp 0x47ff
        },
        0x4892 => {
            m.bx = m.cx; // 4892 mov bx, cx
            m.cx = m.inc(u16, m.cx); // 4894 inc cx
            m.wb(m.bx, 0xF); // 4895 mov byte ptr [bx], 0xf
            continue :sw 0x4898; // falls through
        },
        0x4898 => {
            m.si = m.add(u16, m.si, m.di); // 4898 add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 489A mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 489E or al, al
            if (m.zf) continue :sw 0x4898; // 48A0 je 0x4898
            m.cmp(u8, m.al(), 0x5); // 48A2 cmp al, 5
            if (m.zf) continue :sw 0x4920; // 48A4 je 0x4920
            m.cmp(u8, m.al(), 0xB); // 48A6 cmp al, 0xb
            if (m.zf) continue :sw 0x4866; // 48A8 je 0x4866
            m.cmp(u8, m.al(), 0x4); // 48AA cmp al, 4
            if (m.zf) continue :sw 0x48B2; // 48AC je 0x48b2
            continue :sw 0x4A8C; // 48AE jmp 0x4a8c
        },
        0x48B2 => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 48B2 cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x48CE; // 48B7 je 0x48ce
            m.push(0x48BC);
            run41B6(m, 0x4162); // 48B9 call 0x4162
            if (m.zf) continue :sw 0x48CE; // 48BC je 0x48ce
            m.cmp(u16, m.ax, m.di); // 48BE cmp ax, di
            if (m.zf) continue :sw 0x48CE; // 48C0 je 0x48ce
            m.ax = m.neg(u16, m.ax); // 48C2 neg ax
            m.cmp(u16, m.ax, m.di); // 48C4 cmp ax, di
            if (m.zf) continue :sw 0x48CE; // 48C6 je 0x48ce
            m.wb(m.bp +% 0xFFF4, 0x1); // 48C8 mov byte ptr [bp - 0xc], 1
            continue :sw 0x4880; // 48CC jmp 0x4880
        },
        0x48CE => {
            m.bx = m.dx; // 48CE mov bx, dx
            m.dx = m.inc(u16, m.dx); // 48D0 inc dx
            m.wb(m.bx, 0xF); // 48D1 mov byte ptr [bx], 0xf
            continue :sw 0x480B; // 48D4 jmp 0x480b
        },
        0x48D8 => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 48D8 cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x48F4; // 48DD je 0x48f4
            m.push(0x48E2);
            run41B6(m, 0x4162); // 48DF call 0x4162
            if (m.zf) continue :sw 0x48F4; // 48E2 je 0x48f4
            m.cmp(u16, m.ax, m.di); // 48E4 cmp ax, di
            if (m.zf) continue :sw 0x48F4; // 48E6 je 0x48f4
            m.ax = m.neg(u16, m.ax); // 48E8 neg ax
            m.cmp(u16, m.ax, m.di); // 48EA cmp ax, di
            if (m.zf) continue :sw 0x48F4; // 48EC je 0x48f4
            m.wb(m.bp +% 0xFFF4, 0x1); // 48EE mov byte ptr [bp - 0xc], 1
            continue :sw 0x4880; // 48F2 jmp 0x4880
        },
        0x48F4 => {
            m.wb(m.bp +% 0xFFFC, m.inc(u8, m.rb(m.bp +% 0xFFFC))); // 48F4 inc byte ptr [bp - 4]
            continue :sw 0x4942; // 48F7 jmp 0x4942
        },
        0x4920 => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 4920 cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x493E; // 4925 je 0x493e
            m.push(0x492A);
            run41B6(m, 0x4162); // 4927 call 0x4162
            if (m.zf) continue :sw 0x493E; // 492A je 0x493e
            m.cmp(u16, m.ax, m.di); // 492C cmp ax, di
            if (m.zf) continue :sw 0x493E; // 492E je 0x493e
            m.ax = m.neg(u16, m.ax); // 4930 neg ax
            m.cmp(u16, m.ax, m.di); // 4932 cmp ax, di
            if (m.zf) continue :sw 0x493E; // 4934 je 0x493e
            m.wb(m.bp +% 0xFFF4, 0x1); // 4936 mov byte ptr [bp - 0xc], 1
            continue :sw 0x4880; // 493A jmp 0x4880
        },
        0x493E => {
            m.wb(m.bp +% 0xFFFC, m.add(u8, m.rb(m.bp +% 0xFFFC), 0x10)); // 493E add byte ptr [bp - 4], 0x10
            continue :sw 0x4942; // falls through
        },
        0x4942 => {
            m.si = m.add(u16, m.si, m.di); // 4942 add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 4944 mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 4948 or al, al
            if (m.zf) continue :sw 0x4942; // 494A je 0x4942
            m.cmp(u8, m.al(), 0x4); // 494C cmp al, 4
            if (m.zf) continue :sw 0x48D8; // 494E je 0x48d8
            m.cmp(u8, m.al(), 0x5); // 4950 cmp al, 5
            if (m.zf) continue :sw 0x4920; // 4952 je 0x4920
            continue :sw 0x4880; // 4954 jmp 0x4880
        },
        0x4A06 => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 4A06 cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x4A24; // 4A0B je 0x4a24
            m.push(0x4A10);
            run41B6(m, 0x418C); // 4A0D call 0x418c
            if (m.zf) continue :sw 0x4A24; // 4A10 je 0x4a24
            m.cmp(u16, m.ax, m.di); // 4A12 cmp ax, di
            if (m.zf) continue :sw 0x4A24; // 4A14 je 0x4a24
            m.ax = m.neg(u16, m.ax); // 4A16 neg ax
            m.cmp(u16, m.ax, m.di); // 4A18 cmp ax, di
            if (m.zf) continue :sw 0x4A24; // 4A1A je 0x4a24
            m.wb(m.bp +% 0xFFFA, 0x1); // 4A1C mov byte ptr [bp - 6], 1
            continue :sw 0x4880; // 4A20 jmp 0x4880
        },
        0x4A24 => {
            m.wb(m.bp +% 0xFFEE, m.inc(u8, m.rb(m.bp +% 0xFFEE))); // 4A24 inc byte ptr [bp - 0x12]
            continue :sw 0x4A72; // 4A27 jmp 0x4a72
        },
        0x4A2A => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 4A2A cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x4A48; // 4A2F je 0x4a48
            m.push(0x4A34);
            run41B6(m, 0x4162); // 4A31 call 0x4162
            if (m.zf) continue :sw 0x4A48; // 4A34 je 0x4a48
            m.cmp(u16, m.ax, m.di); // 4A36 cmp ax, di
            if (m.zf) continue :sw 0x4A48; // 4A38 je 0x4a48
            m.ax = m.neg(u16, m.ax); // 4A3A neg ax
            m.cmp(u16, m.ax, m.di); // 4A3C cmp ax, di
            if (m.zf) continue :sw 0x4A48; // 4A3E je 0x4a48
            m.wb(m.bp +% 0xFFF4, 0x1); // 4A40 mov byte ptr [bp - 0xc], 1
            continue :sw 0x4880; // 4A44 jmp 0x4880
        },
        0x4A48 => {
            m.bx = m.dx; // 4A48 mov bx, dx
            m.dx = m.inc(u16, m.dx); // 4A4A inc dx
            m.wb(m.bx, 0xF); // 4A4B mov byte ptr [bx], 0xf
            continue :sw 0x4A72; // 4A4E jmp 0x4a72
        },
        0x4A50 => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 4A50 cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x4A6E; // 4A55 je 0x4a6e
            m.push(0x4A5A);
            run41B6(m, 0x418C); // 4A57 call 0x418c
            if (m.zf) continue :sw 0x4A6E; // 4A5A je 0x4a6e
            m.cmp(u16, m.ax, m.di); // 4A5C cmp ax, di
            if (m.zf) continue :sw 0x4A6E; // 4A5E je 0x4a6e
            m.ax = m.neg(u16, m.ax); // 4A60 neg ax
            m.cmp(u16, m.ax, m.di); // 4A62 cmp ax, di
            if (m.zf) continue :sw 0x4A6E; // 4A64 je 0x4a6e
            m.wb(m.bp +% 0xFFFA, 0x1); // 4A66 mov byte ptr [bp - 6], 1
            continue :sw 0x4880; // 4A6A jmp 0x4880
        },
        0x4A6E => {
            m.wb(m.bp +% 0xFFEE, m.add(u8, m.rb(m.bp +% 0xFFEE), 0x10)); // 4A6E add byte ptr [bp - 0x12], 0x10
            continue :sw 0x4A72; // falls through
        },
        0x4A72 => {
            m.si = m.add(u16, m.si, m.di); // 4A72 add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 4A74 mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 4A78 or al, al
            if (m.zf) continue :sw 0x4A72; // 4A7A je 0x4a72
            m.cmp(u8, m.al(), 0x4); // 4A7C cmp al, 4
            if (m.zf) continue :sw 0x4A2A; // 4A7E je 0x4a2a
            m.cmp(u8, m.al(), 0x5); // 4A80 cmp al, 5
            if (m.zf) continue :sw 0x4ADC; // 4A82 je 0x4adc
            m.cmp(u8, m.al(), 0xB); // 4A84 cmp al, 0xb
            if (!m.zf) continue :sw 0x4A8C; // 4A86 jne 0x4a8c
            continue :sw 0x4A06; // 4A88 jmp 0x4a06
        },
        0x4A8C => {
            m.cmp(u8, m.al(), 0xC); // 4A8C cmp al, 0xc
            if (m.zf) continue :sw 0x4A50; // 4A8E je 0x4a50
            continue :sw 0x4880; // 4A90 jmp 0x4880
        },
        0x4A94 => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 4A94 cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x4AB2; // 4A99 je 0x4ab2
            m.push(0x4A9E);
            run41B6(m, 0x4162); // 4A9B call 0x4162
            if (m.zf) continue :sw 0x4AB2; // 4A9E je 0x4ab2
            m.cmp(u16, m.ax, m.di); // 4AA0 cmp ax, di
            if (m.zf) continue :sw 0x4AB2; // 4AA2 je 0x4ab2
            m.ax = m.neg(u16, m.ax); // 4AA4 neg ax
            m.cmp(u16, m.ax, m.di); // 4AA6 cmp ax, di
            if (m.zf) continue :sw 0x4AB2; // 4AA8 je 0x4ab2
            m.wb(m.bp +% 0xFFF4, 0x1); // 4AAA mov byte ptr [bp - 0xc], 1
            continue :sw 0x4880; // 4AAE jmp 0x4880
        },
        0x4AB2 => {
            m.wb(m.bp +% 0xFFFC, m.inc(u8, m.rb(m.bp +% 0xFFFC))); // 4AB2 inc byte ptr [bp - 4]
            continue :sw 0x4AFE; // 4AB5 jmp 0x4afe
        },
        0x4AB8 => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 4AB8 cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x4AD6; // 4ABD je 0x4ad6
            m.push(0x4AC2);
            run41B6(m, 0x418C); // 4ABF call 0x418c
            if (m.zf) continue :sw 0x4AD6; // 4AC2 je 0x4ad6
            m.cmp(u16, m.ax, m.di); // 4AC4 cmp ax, di
            if (m.zf) continue :sw 0x4AD6; // 4AC6 je 0x4ad6
            m.ax = m.neg(u16, m.ax); // 4AC8 neg ax
            m.cmp(u16, m.ax, m.di); // 4ACA cmp ax, di
            if (m.zf) continue :sw 0x4AD6; // 4ACC je 0x4ad6
            m.wb(m.bp +% 0xFFFA, 0x1); // 4ACE mov byte ptr [bp - 6], 1
            continue :sw 0x4880; // 4AD2 jmp 0x4880
        },
        0x4AD6 => {
            m.wb(m.bp +% 0xFFEE, m.inc(u8, m.rb(m.bp +% 0xFFEE))); // 4AD6 inc byte ptr [bp - 0x12]
            continue :sw 0x4AFE; // 4AD9 jmp 0x4afe
        },
        0x4ADC => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 4ADC cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x4AFA; // 4AE1 je 0x4afa
            m.push(0x4AE6);
            run41B6(m, 0x4162); // 4AE3 call 0x4162
            if (m.zf) continue :sw 0x4AFA; // 4AE6 je 0x4afa
            m.cmp(u16, m.ax, m.di); // 4AE8 cmp ax, di
            if (m.zf) continue :sw 0x4AFA; // 4AEA je 0x4afa
            m.ax = m.neg(u16, m.ax); // 4AEC neg ax
            m.cmp(u16, m.ax, m.di); // 4AEE cmp ax, di
            if (m.zf) continue :sw 0x4AFA; // 4AF0 je 0x4afa
            m.wb(m.bp +% 0xFFF4, 0x1); // 4AF2 mov byte ptr [bp - 0xc], 1
            continue :sw 0x4880; // 4AF6 jmp 0x4880
        },
        0x4AFA => {
            m.wb(m.bp +% 0xFFFC, m.add(u8, m.rb(m.bp +% 0xFFFC), 0x10)); // 4AFA add byte ptr [bp - 4], 0x10
            continue :sw 0x4AFE; // falls through
        },
        0x4AFE => {
            m.si = m.add(u16, m.si, m.di); // 4AFE add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 4B00 mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 4B04 or al, al
            if (m.zf) continue :sw 0x4AFE; // 4B06 je 0x4afe
            m.cmp(u8, m.al(), 0x4); // 4B08 cmp al, 4
            if (m.zf) continue :sw 0x4A94; // 4B0A je 0x4a94
            m.cmp(u8, m.al(), 0x5); // 4B0C cmp al, 5
            if (m.zf) continue :sw 0x4ADC; // 4B0E je 0x4adc
            m.cmp(u8, m.al(), 0xB); // 4B10 cmp al, 0xb
            if (m.zf) continue :sw 0x4AB8; // 4B12 je 0x4ab8
            m.cmp(u8, m.al(), 0xC); // 4B14 cmp al, 0xc
            if (m.zf) continue :sw 0x4B1C; // 4B16 je 0x4b1c
            continue :sw 0x4880; // 4B18 jmp 0x4880
        },
        0x4B1C => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 4B1C cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x4B3A; // 4B21 je 0x4b3a
            m.push(0x4B26);
            run41B6(m, 0x418C); // 4B23 call 0x418c
            if (m.zf) continue :sw 0x4B3A; // 4B26 je 0x4b3a
            m.cmp(u16, m.ax, m.di); // 4B28 cmp ax, di
            if (m.zf) continue :sw 0x4B3A; // 4B2A je 0x4b3a
            m.ax = m.neg(u16, m.ax); // 4B2C neg ax
            m.cmp(u16, m.ax, m.di); // 4B2E cmp ax, di
            if (m.zf) continue :sw 0x4B3A; // 4B30 je 0x4b3a
            m.wb(m.bp +% 0xFFFA, 0x1); // 4B32 mov byte ptr [bp - 6], 1
            continue :sw 0x4880; // 4B36 jmp 0x4880
        },
        0x4B3A => {
            m.wb(m.bp +% 0xFFEE, m.add(u8, m.rb(m.bp +% 0xFFEE), 0x10)); // 4B3A add byte ptr [bp - 0x12], 0x10
            continue :sw 0x4AFE; // 4B3E jmp 0x4afe
        },
        0x4B40 => {
            m.cmp(u8, m.rb(m.bp +% 0xFFFE), 0x0); // 4B40 cmp byte ptr [bp - 2], 0
            if (!m.zf) continue :sw 0x4B4C; // 4B44 jne 0x4b4c
            m.cmp(u8, m.rb(m.bp +% 0xFFFC), 0x0); // 4B46 cmp byte ptr [bp - 4], 0
            if (m.zf) continue :sw 0x4B98; // 4B4A je 0x4b98
            continue :sw 0x4B4C; // falls through
        },
        0x4B4C => {
            m.@"test"(u8, m.rb(m.bp +% 0xFFFE), 0xF); // 4B4C test byte ptr [bp - 2], 0xf
            if (m.zf) continue :sw 0x4B62; // 4B50 je 0x4b62
            m.bx = m.dx; // 4B52 mov bx, dx
            m.dx = m.inc(u16, m.dx); // 4B54 inc dx
            m.wb(m.bx, 0x1B); // 4B55 mov byte ptr [bx], 0x1b
            m.bx = m.dx; // 4B58 mov bx, dx
            m.dx = m.inc(u16, m.dx); // 4B5A inc dx
            m.wb(m.bx, 0x9); // 4B5B mov byte ptr [bx], 9
            m.wb(m.bp +% 0xFFFE, m.sub(u8, m.rb(m.bp +% 0xFFFE), 0x11)); // 4B5E sub byte ptr [bp - 2], 0x11
            continue :sw 0x4B62; // falls through
        },
        0x4B62 => {
            m.setAl(m.rb(m.bp +% 0xFFFC)); // 4B62 mov al, byte ptr [bp - 4]
            m.@"test"(u8, m.al(), 0xF); // 4B65 test al, 0xf
            if (m.zf) continue :sw 0x4B86; // 4B67 je 0x4b86
            m.bx = m.dx; // 4B69 mov bx, dx
            m.dx = m.inc(u16, m.dx); // 4B6B inc dx
            m.wb(m.bx, 0x1B); // 4B6C mov byte ptr [bx], 0x1b
            m.bx = m.dx; // 4B6F mov bx, dx
            m.dx = m.inc(u16, m.dx); // 4B71 inc dx
            m.wb(m.bx, 0xF); // 4B72 mov byte ptr [bx], 0xf
            m.setAl(m.sub(u8, m.al(), 0x11)); // 4B75 sub al, 0x11
            continue :sw 0x4B82; // 4B77 jmp 0x4b82
        },
        0x4B7A => {
            m.bx = m.dx; // 4B7A mov bx, dx
            m.dx = m.inc(u16, m.dx); // 4B7C inc dx
            m.wb(m.bx, 0xF); // 4B7D mov byte ptr [bx], 0xf
            m.setAl(m.dec(u8, m.al())); // 4B80 dec al
            continue :sw 0x4B82; // falls through
        },
        0x4B82 => {
            m.@"test"(u8, m.al(), 0xF); // 4B82 test al, 0xf
            if (!m.zf) continue :sw 0x4B7A; // 4B84 jne 0x4b7a
            continue :sw 0x4B86; // falls through
        },
        0x4B86 => {
            m.setAl(m.add(u8, m.al(), m.rb(m.bp +% 0xFFFE))); // 4B86 add al, byte ptr [bp - 2]
            continue :sw 0x4B94; // 4B89 jmp 0x4b94
        },
        0x4B8C => {
            m.bx = m.dx; // 4B8C mov bx, dx
            m.dx = m.inc(u16, m.dx); // 4B8E inc dx
            m.wb(m.bx, 0x1B); // 4B8F mov byte ptr [bx], 0x1b
            m.setAl(m.sub(u8, m.al(), 0x10)); // 4B92 sub al, 0x10
            continue :sw 0x4B94; // falls through
        },
        0x4B94 => {
            m.cmp(u8, m.al(), 0x0); // 4B94 cmp al, 0
            if (!m.zf and m.sf == m.of) continue :sw 0x4B8C; // 4B96 jg 0x4b8c
            continue :sw 0x4B98; // falls through
        },
        0x4B98 => {
            m.cmp(u8, m.rb(m.bp +% 0xFFFA), 0x0); // 4B98 cmp byte ptr [bp - 6], 0
            if (!m.zf) continue :sw 0x4BB5; // 4B9C jne 0x4bb5
            m.setBl(m.rb(0xA041)); // 4B9E mov bl, byte ptr [0xa041]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 4BA2 sub bh, bh
            m.bx = m.sub(u16, m.bx, m.si); // 4BA4 sub bx, si
            m.bx = m.neg(u16, m.bx); // 4BA6 neg bx
            m.cmp(u8, m.rb(m.bx +% 0x0CFF), 0x0); // 4BA8 cmp byte ptr [bx + 0xcff], 0
            if (m.zf) continue :sw 0x4BB5; // 4BAD je 0x4bb5
            m.bx = m.dx; // 4BAF mov bx, dx
            m.dx = m.inc(u16, m.dx); // 4BB1 inc dx
            m.wb(m.bx, 0x1E); // 4BB2 mov byte ptr [bx], 0x1e
            continue :sw 0x4BB5; // falls through
        },
        0x4BB5 => {
            m.bx = m.dx; // 4BB5 mov bx, dx
            m.wb(m.bx, 0x0); // 4BB7 mov byte ptr [bx], 0
            m.cmp(u8, m.rb(m.bp +% 0xFFF6), 0x0); // 4BBA cmp byte ptr [bp - 0xa], 0
            if (!m.zf) continue :sw 0x4BC6; // 4BBE jne 0x4bc6
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // 4BC0 cmp byte ptr [bp - 0x12], 0
            if (m.zf) continue :sw 0x4C12; // 4BC4 je 0x4c12
            continue :sw 0x4BC6; // falls through
        },
        0x4BC6 => {
            m.@"test"(u8, m.rb(m.bp +% 0xFFF6), 0xF); // 4BC6 test byte ptr [bp - 0xa], 0xf
            if (m.zf) continue :sw 0x4BDC; // 4BCA je 0x4bdc
            m.bx = m.cx; // 4BCC mov bx, cx
            m.cx = m.inc(u16, m.cx); // 4BCE inc cx
            m.wb(m.bx, 0x1B); // 4BCF mov byte ptr [bx], 0x1b
            m.bx = m.cx; // 4BD2 mov bx, cx
            m.cx = m.inc(u16, m.cx); // 4BD4 inc cx
            m.wb(m.bx, 0x9); // 4BD5 mov byte ptr [bx], 9
            m.wb(m.bp +% 0xFFF6, m.sub(u8, m.rb(m.bp +% 0xFFF6), 0x11)); // 4BD8 sub byte ptr [bp - 0xa], 0x11
            continue :sw 0x4BDC; // falls through
        },
        0x4BDC => {
            m.setAl(m.rb(m.bp +% 0xFFEE)); // 4BDC mov al, byte ptr [bp - 0x12]
            m.@"test"(u8, m.al(), 0xF); // 4BDF test al, 0xf
            if (m.zf) continue :sw 0x4C00; // 4BE1 je 0x4c00
            m.bx = m.cx; // 4BE3 mov bx, cx
            m.cx = m.inc(u16, m.cx); // 4BE5 inc cx
            m.wb(m.bx, 0x1B); // 4BE6 mov byte ptr [bx], 0x1b
            m.bx = m.cx; // 4BE9 mov bx, cx
            m.cx = m.inc(u16, m.cx); // 4BEB inc cx
            m.wb(m.bx, 0xF); // 4BEC mov byte ptr [bx], 0xf
            m.setAl(m.sub(u8, m.al(), 0x11)); // 4BEF sub al, 0x11
            continue :sw 0x4BFC; // 4BF1 jmp 0x4bfc
        },
        0x4BF4 => {
            m.bx = m.cx; // 4BF4 mov bx, cx
            m.cx = m.inc(u16, m.cx); // 4BF6 inc cx
            m.wb(m.bx, 0xF); // 4BF7 mov byte ptr [bx], 0xf
            m.setAl(m.dec(u8, m.al())); // 4BFA dec al
            continue :sw 0x4BFC; // falls through
        },
        0x4BFC => {
            m.@"test"(u8, m.al(), 0xF); // 4BFC test al, 0xf
            if (!m.zf) continue :sw 0x4BF4; // 4BFE jne 0x4bf4
            continue :sw 0x4C00; // falls through
        },
        0x4C00 => {
            m.setAl(m.add(u8, m.al(), m.rb(m.bp +% 0xFFF6))); // 4C00 add al, byte ptr [bp - 0xa]
            continue :sw 0x4C0E; // 4C03 jmp 0x4c0e
        },
        0x4C06 => {
            m.bx = m.cx; // 4C06 mov bx, cx
            m.cx = m.inc(u16, m.cx); // 4C08 inc cx
            m.wb(m.bx, 0x1B); // 4C09 mov byte ptr [bx], 0x1b
            m.setAl(m.sub(u8, m.al(), 0x10)); // 4C0C sub al, 0x10
            continue :sw 0x4C0E; // falls through
        },
        0x4C0E => {
            m.cmp(u8, m.al(), 0x0); // 4C0E cmp al, 0
            if (!m.zf and m.sf == m.of) continue :sw 0x4C06; // 4C10 jg 0x4c06
            continue :sw 0x4C12; // falls through
        },
        0x4C12 => {
            m.cmp(u8, m.rb(m.bp +% 0xFFF4), 0x0); // 4C12 cmp byte ptr [bp - 0xc], 0
            if (!m.zf) continue :sw 0x4C2F; // 4C16 jne 0x4c2f
            m.setBl(m.rb(0xA051)); // 4C18 mov bl, byte ptr [0xa051]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 4C1C sub bh, bh
            m.bx = m.sub(u16, m.bx, m.si); // 4C1E sub bx, si
            m.bx = m.neg(u16, m.bx); // 4C20 neg bx
            m.cmp(u8, m.rb(m.bx +% 0x0CFF), 0x0); // 4C22 cmp byte ptr [bx + 0xcff], 0
            if (m.zf) continue :sw 0x4C2F; // 4C27 je 0x4c2f
            m.bx = m.cx; // 4C29 mov bx, cx
            m.cx = m.inc(u16, m.cx); // 4C2B inc cx
            m.wb(m.bx, 0x1E); // 4C2C mov byte ptr [bx], 0x1e
            continue :sw 0x4C2F; // falls through
        },
        0x4C2F => {
            m.bx = m.cx; // 4C2F mov bx, cx
            m.wb(m.bx, 0x0); // 4C31 mov byte ptr [bx], 0
            m.di = m.sub(u16, m.di, m.di); // 4C34 sub di, di
            m.bx = 0x70E5; // 4C36 mov bx, 0x70e5
            m.bp = 0xB4E6; // 4C39 mov bp, 0xb4e6
            continue :sw 0x4C55; // 4C3C jmp 0x4c55
        },
        0x4C3E => {
            m.setAl(m.rb(m.bx +% m.di)); // 4C3E mov al, byte ptr [bx + di]
            m.setAl(m.sub(u8, m.al(), m.rb(m.di +% 0x9FEC))); // 4C40 sub al, byte ptr [di - 0x6014]
            m.wb(m.bp +% m.di, m.al()); // 4C44 mov byte ptr [bp + di], al
            m.cmp(u8, m.rb(m.di +% 0x9FED), 0x0); // 4C46 cmp byte ptr [di - 0x6013], 0
            if (m.zf) continue :sw 0x4C65; // 4C4B je 0x4c65
            m.setAl(m.add(u8, m.al(), m.rb(m.di +% 0xA060))); // 4C4D add al, byte ptr [di - 0x5fa0]
            m.wb(m.bx +% m.di +% 0x0001, m.al()); // 4C51 mov byte ptr [bx + di + 1], al
            m.di = m.inc(u16, m.di); // 4C54 inc di
            continue :sw 0x4C55; // falls through
        },
        0x4C55 => {
            m.cmp(u16, m.di, 0xA); // 4C55 cmp di, 0xa
            if (m.sf == m.of) continue :sw 0x4C65; // 4C58 jge 0x4c65
            m.cmp(u8, m.rb(m.di +% 0xA060), 0x0); // 4C5A cmp byte ptr [di - 0x5fa0], 0
            if (!m.zf) continue :sw 0x4C3E; // 4C5F jne 0x4c3e
            m.setAl(m.rb(m.bx +% m.di)); // 4C61 mov al, byte ptr [bx + di]
            m.wb(m.bp +% m.di, m.al()); // 4C63 mov byte ptr [bp + di], al
            continue :sw 0x4C65; // falls through
        },
        0x4C65 => {
            m.setAl(0xE5); // 4C65 mov al, 0xe5
            m.si = m.sub(u16, m.si, m.si); // 4C67 sub si, si
            m.dx = m.si; // 4C69 mov dx, si
            continue :sw 0x4C77; // 4C6B jmp 0x4c77
        },
        0x4C6E => {
            m.cmp(u8, m.rb(m.bp +% m.si), m.al()); // 4C6E cmp byte ptr [bp + si], al
            if (m.zf or m.sf != m.of) continue :sw 0x4C76; // 4C70 jle 0x4c76
            m.setAl(m.rb(m.bp +% m.si)); // 4C72 mov al, byte ptr [bp + si]
            m.dx = m.si; // 4C74 mov dx, si
            continue :sw 0x4C76; // falls through
        },
        0x4C76 => {
            m.si = m.inc(u16, m.si); // 4C76 inc si
            continue :sw 0x4C77; // falls through
        },
        0x4C77 => {
            m.cmp(u16, m.si, m.di); // 4C77 cmp si, di
            if (m.zf or m.sf != m.of) continue :sw 0x4C6E; // 4C79 jle 0x4c6e
            m.di = m.dx; // 4C7B mov di, dx
            continue :sw 0x4C87; // 4C7D jmp 0x4c87
        },
        0x4C80 => {
            m.cmp(u8, m.rb(m.bx +% m.di), m.al()); // 4C80 cmp byte ptr [bx + di], al
            if (m.sf == m.of) continue :sw 0x4C86; // 4C82 jge 0x4c86
            m.setAl(m.rb(m.bx +% m.di)); // 4C84 mov al, byte ptr [bx + di]
            continue :sw 0x4C86; // falls through
        },
        0x4C86 => {
            m.di = m.dec(u16, m.di); // 4C86 dec di
            continue :sw 0x4C87; // falls through
        },
        0x4C87 => {
            m.di = m.@"or"(u16, m.di, m.di); // 4C87 or di, di
            if (m.sf == m.of) continue :sw 0x4C80; // 4C89 jge 0x4c80
            m.cbw(); // 4C8B cbw
            continue :sw 0x4C8C; // falls through
        },
        0x4C8C => {
            m.dx = m.pop(); // 4C8C pop dx
            m.cx = m.pop(); // 4C8D pop cx
            m.bx = m.pop(); // 4C8E pop bx
            m.si = m.pop(); // 4C8F pop si
            m.di = m.pop(); // 4C90 pop di
            m.sp = m.add(u16, m.sp, 0x1C); // 4C91 add sp, 0x1c
            m.bp = m.pop(); // 4C94 pop bp
            return; // 4C95 retf 4
        },
        else => unreachable,
    }
}

/// 4793:4C98-57AB, from the label `start` until its `retf` (or, for a near
/// helper entered by `call`, its `ret`).
pub fn run4CEC(m: *Machine, start: u16) void {
    @setEvalBranchQuota(1_000_000);
    sw: switch (start) {
        0x4C98 => {
            m.push(m.di); // 4C98 push di
            m.push(m.si); // 4C99 push si
            m.di = m.si; // 4C9A mov di, si
            m.di = m.add(u16, m.di, 0x9EF6); // 4C9C add di, 0x9ef6
            m.setAl(m.rb(m.si +% 0xA09E)); // 4CA0 mov al, byte ptr [si - 0x5f62]
            m.cbw(); // 4CA4 cbw
            m.si = m.ax; // 4CA5 mov si, ax
            m.setAl(m.rb(m.si +% 0x0490)); // 4CA7 mov al, byte ptr [si + 0x490]
            m.cbw(); // 4CAB cbw
            continue :sw 0x4CAC; // falls through
        },
        0x4CAC => {
            m.di = m.add(u16, m.di, m.ax); // 4CAC add di, ax
            m.cmp(u8, m.rb(m.di), 0x0); // 4CAE cmp byte ptr [di], 0
            if (m.zf) continue :sw 0x4CAC; // 4CB1 je 0x4cac
            m.setBl(m.rb(m.di)); // 4CB3 mov bl, byte ptr [di]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 4CB5 sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 4CB7 mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.rb(m.si +% 0x047E), m.bl()); // 4CBB test byte ptr [si + 0x47e], bl
            m.si = m.pop(); // 4CBF pop si
            m.di = m.pop(); // 4CC0 pop di
            _ = m.pop();
            return; // 4CC1 ret
        },
        0x4CC2 => {
            m.push(m.di); // 4CC2 push di
            m.push(m.si); // 4CC3 push si
            m.di = m.si; // 4CC4 mov di, si
            m.di = m.add(u16, m.di, 0x9EF6); // 4CC6 add di, 0x9ef6
            m.setAl(m.rb(m.si +% 0xA164)); // 4CCA mov al, byte ptr [si - 0x5e9c]
            m.cbw(); // 4CCE cbw
            m.si = m.ax; // 4CCF mov si, ax
            m.setAl(m.rb(m.si +% 0x0490)); // 4CD1 mov al, byte ptr [si + 0x490]
            m.cbw(); // 4CD5 cbw
            continue :sw 0x4CD6; // falls through
        },
        0x4CD6 => {
            m.di = m.add(u16, m.di, m.ax); // 4CD6 add di, ax
            m.cmp(u8, m.rb(m.di), 0x0); // 4CD8 cmp byte ptr [di], 0
            if (m.zf) continue :sw 0x4CD6; // 4CDB je 0x4cd6
            m.setBl(m.rb(m.di)); // 4CDD mov bl, byte ptr [di]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 4CDF sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 4CE1 mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.rb(m.si +% 0x047E), m.bl()); // 4CE5 test byte ptr [si + 0x47e], bl
            m.si = m.pop(); // 4CE9 pop si
            m.di = m.pop(); // 4CEA pop di
            _ = m.pop();
            return; // 4CEB ret
        },
        0x4CEC => {
            m.push(m.bp); // 4CEC push bp
            m.bp = m.sp; // 4CED mov bp, sp
            m.sp = m.sub(u16, m.sp, 0x1C); // 4CEF sub sp, 0x1c
            m.push(m.di); // 4CF2 push di
            m.push(m.si); // 4CF3 push si
            m.push(m.bx); // 4CF4 push bx
            m.push(m.cx); // 4CF5 push cx
            m.push(m.dx); // 4CF6 push dx
            m.si = m.rw(m.bp +% 0x0006); // 4CF7 mov si, word ptr [bp + 6]
            m.setAl(m.rb(m.si +% 0x9EF6)); // 4CFA mov al, byte ptr [si - 0x610a]
            m.cbw(); // 4CFE cbw
            m.bx = m.ax; // 4CFF mov bx, ax
            m.setAl(m.rb(m.bx +% 0x1A71)); // 4D01 mov al, byte ptr [bx + 0x1a71]
            m.wb(0x70E5, m.al()); // 4D05 mov byte ptr [0x70e5], al
            m.cmp(u8, m.rb(m.bp +% 0x0008), m.al()); // 4D08 cmp byte ptr [bp + 8], al
            if (m.sf == m.of) continue :sw 0x4D1C; // 4D0B jge 0x4d1c
            m.setAl(m.rb(m.bp +% 0x0008)); // 4D0D mov al, byte ptr [bp + 8]
            m.cbw(); // 4D10 cbw
            m.cx = m.ax; // 4D11 mov cx, ax
            m.setAl(m.rb(0x70E5)); // 4D13 mov al, byte ptr [0x70e5]
            m.cbw(); // 4D16 cbw
            m.ax = m.sub(u16, m.ax, m.cx); // 4D17 sub ax, cx
            continue :sw 0x57A0; // 4D19 jmp 0x57a0
        },
        0x4D1C => {
            m.dx = 0x9FEC; // 4D1C mov dx, 0x9fec
            m.bx = m.dx; // 4D1F mov bx, dx
            m.dx = m.inc(u16, m.dx); // 4D21 inc dx
            m.setAl(m.rb(m.bp +% 0x0008)); // 4D22 mov al, byte ptr [bp + 8]
            m.wb(m.bx, m.al()); // 4D25 mov byte ptr [bx], al
            m.cx = 0xA060; // 4D27 mov cx, 0xa060
            m.setAl(m.sub(u8, m.al(), m.al())); // 4D2A sub al, al
            m.wb(0xA060, m.al()); // 4D2C mov byte ptr [0xa060], al
            m.wb(m.bp +% 0xFFFA, m.al()); // 4D2F mov byte ptr [bp - 6], al
            m.wb(m.bp +% 0xFFF4, m.al()); // 4D32 mov byte ptr [bp - 0xc], al
            m.cmp(u8, m.rb(m.si +% 0x37DA), 0x0); // 4D35 cmp byte ptr [si + 0x37da], 0
            if (!m.zf) continue :sw 0x4D40; // 4D3A jne 0x4d40
            continue :sw 0x4DD8; // 4D3C jmp 0x4dd8
        },
        0x4D40 => {
            m.cmp(u8, m.rb(m.si +% 0x9EFF), 0x8); // 4D40 cmp byte ptr [si - 0x6101], 8
            if (!m.zf) continue :sw 0x4D8C; // 4D45 jne 0x4d8c
            m.cmp(u8, m.rb(m.si +% 0xA16D), 0x0); // 4D47 cmp byte ptr [si - 0x5e93], 0
            if (m.zf) continue :sw 0x4D86; // 4D4C je 0x4d86
            m.di = m.si; // 4D4E mov di, si
            m.di = m.add(u16, m.di, 0x9); // 4D50 add di, 9
            m.setAl(m.rb(m.di +% 0xA164)); // 4D53 mov al, byte ptr [di - 0x5e9c]
            m.cbw(); // 4D57 cbw
            m.bx = m.ax; // 4D58 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // 4D5A mov al, byte ptr [bx + 0x490]
            m.cbw(); // 4D5E cbw
            m.cmp(u16, m.ax, 0xFFF7); // 4D5F cmp ax, 0xfff7
            if (m.zf) continue :sw 0x4D86; // 4D62 je 0x4d86
            continue :sw 0x4D64; // falls through
        },
        0x4D64 => {
            m.di = m.add(u16, m.di, m.ax); // 4D64 add di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // 4D66 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0x4D64; // 4D6B je 0x4d64
            m.setAl(m.rb(m.bx +% 0x047E)); // 4D6D mov al, byte ptr [bx + 0x47e]
            m.setBl(m.rb(m.di +% 0x9EF6)); // 4D71 mov bl, byte ptr [di - 0x610a]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 4D75 sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 4D77 mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.bl(), m.al()); // 4D7B test bl, al
            if (m.zf) continue :sw 0x4D86; // 4D7D je 0x4d86
            m.wb(m.bp +% 0xFFFA, 0x1); // 4D7F mov byte ptr [bp - 6], 1
            continue :sw 0x4D8C; // 4D83 jmp 0x4d8c
        },
        0x4D86 => {
            m.bx = m.dx; // 4D86 mov bx, dx
            m.dx = m.inc(u16, m.dx); // 4D88 inc dx
            m.wb(m.bx, 0x3); // 4D89 mov byte ptr [bx], 3
            continue :sw 0x4D8C; // falls through
        },
        0x4D8C => {
            m.cmp(u8, m.rb(m.si +% 0x9F01), 0x8); // 4D8C cmp byte ptr [si - 0x60ff], 8
            if (!m.zf) continue :sw 0x4DD8; // 4D91 jne 0x4dd8
            m.cmp(u8, m.rb(m.si +% 0xA16F), 0x0); // 4D93 cmp byte ptr [si - 0x5e91], 0
            if (m.zf) continue :sw 0x4DD2; // 4D98 je 0x4dd2
            m.di = m.si; // 4D9A mov di, si
            m.di = m.add(u16, m.di, 0xB); // 4D9C add di, 0xb
            m.setAl(m.rb(m.di +% 0xA164)); // 4D9F mov al, byte ptr [di - 0x5e9c]
            m.cbw(); // 4DA3 cbw
            m.bx = m.ax; // 4DA4 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // 4DA6 mov al, byte ptr [bx + 0x490]
            m.cbw(); // 4DAA cbw
            m.cmp(u16, m.ax, 0xFFF5); // 4DAB cmp ax, 0xfff5
            if (m.zf) continue :sw 0x4DD2; // 4DAE je 0x4dd2
            continue :sw 0x4DB0; // falls through
        },
        0x4DB0 => {
            m.di = m.add(u16, m.di, m.ax); // 4DB0 add di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // 4DB2 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0x4DB0; // 4DB7 je 0x4db0
            m.setAl(m.rb(m.bx +% 0x047E)); // 4DB9 mov al, byte ptr [bx + 0x47e]
            m.setBl(m.rb(m.di +% 0x9EF6)); // 4DBD mov bl, byte ptr [di - 0x610a]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 4DC1 sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 4DC3 mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.bl(), m.al()); // 4DC7 test bl, al
            if (m.zf) continue :sw 0x4DD2; // 4DC9 je 0x4dd2
            m.wb(m.bp +% 0xFFFA, 0x1); // 4DCB mov byte ptr [bp - 6], 1
            continue :sw 0x4DD8; // 4DCF jmp 0x4dd8
        },
        0x4DD2 => {
            m.bx = m.dx; // 4DD2 mov bx, dx
            m.dx = m.inc(u16, m.dx); // 4DD4 inc dx
            m.wb(m.bx, 0x3); // 4DD5 mov byte ptr [bx], 3
            continue :sw 0x4DD8; // falls through
        },
        0x4DD8 => {
            m.setAl(m.rb(0xA04A)); // 4DD8 mov al, byte ptr [0xa04a]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // 4DDB sub ah, ah
            m.di = m.ax; // 4DDD mov di, ax
            m.bx = m.si; // 4DDF mov bx, si
            m.bx = m.sub(u16, m.bx, m.di); // 4DE1 sub bx, di
            m.cmp(u8, m.rb(m.bx +% 0x0A68), m.ah()); // 4DE3 cmp byte ptr [bx + 0xa68], ah
            if (m.zf) continue :sw 0x4E26; // 4DE7 je 0x4e26
            m.cmp(u8, m.rb(m.di +% 0xA164), m.ah()); // 4DE9 cmp byte ptr [di - 0x5e9c], ah
            if (m.zf) continue :sw 0x4E20; // 4DED je 0x4e20
            m.setAl(m.rb(m.di +% 0xA164)); // 4DEF mov al, byte ptr [di - 0x5e9c]
            m.cbw(); // 4DF3 cbw
            m.si = m.ax; // 4DF4 mov si, ax
            m.setAl(m.rb(m.si +% 0x0490)); // 4DF6 mov al, byte ptr [si + 0x490]
            m.cbw(); // 4DFA cbw
            continue :sw 0x4DFB; // falls through
        },
        0x4DFB => {
            m.di = m.add(u16, m.di, m.ax); // 4DFB add di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // 4DFD cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0x4DFB; // 4E02 je 0x4dfb
            m.setAl(m.rb(m.si +% 0x047E)); // 4E04 mov al, byte ptr [si + 0x47e]
            m.si = m.rw(m.bp +% 0x0006); // 4E08 mov si, word ptr [bp + 6]
            m.setBl(m.rb(m.di +% 0x9EF6)); // 4E0B mov bl, byte ptr [di - 0x610a]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 4E0F sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 4E11 mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.bl(), m.al()); // 4E15 test bl, al
            if (m.zf) continue :sw 0x4E20; // 4E17 je 0x4e20
            m.wb(m.bp +% 0xFFFA, 0x1); // 4E19 mov byte ptr [bp - 6], 1
            continue :sw 0x4E26; // 4E1D jmp 0x4e26
        },
        0x4E20 => {
            m.bx = m.dx; // 4E20 mov bx, dx
            m.dx = m.inc(u16, m.dx); // 4E22 inc dx
            m.wb(m.bx, 0x9); // 4E23 mov byte ptr [bx], 9
            continue :sw 0x4E26; // falls through
        },
        0x4E26 => {
            m.setAl(m.rb(0xA04B)); // 4E26 mov al, byte ptr [0xa04b]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // 4E29 sub ah, ah
            m.di = m.ax; // 4E2B mov di, ax
            m.bx = m.si; // 4E2D mov bx, si
            m.bx = m.sub(u16, m.bx, m.di); // 4E2F sub bx, di
            m.cmp(u8, m.rb(m.bx +% 0x0A68), m.ah()); // 4E31 cmp byte ptr [bx + 0xa68], ah
            if (m.zf) continue :sw 0x4E74; // 4E35 je 0x4e74
            m.cmp(u8, m.rb(m.di +% 0xA164), m.ah()); // 4E37 cmp byte ptr [di - 0x5e9c], ah
            if (m.zf) continue :sw 0x4E6E; // 4E3B je 0x4e6e
            m.setAl(m.rb(m.di +% 0xA164)); // 4E3D mov al, byte ptr [di - 0x5e9c]
            m.cbw(); // 4E41 cbw
            m.si = m.ax; // 4E42 mov si, ax
            m.setAl(m.rb(m.si +% 0x0490)); // 4E44 mov al, byte ptr [si + 0x490]
            m.cbw(); // 4E48 cbw
            continue :sw 0x4E49; // falls through
        },
        0x4E49 => {
            m.di = m.add(u16, m.di, m.ax); // 4E49 add di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // 4E4B cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0x4E49; // 4E50 je 0x4e49
            m.setAl(m.rb(m.si +% 0x047E)); // 4E52 mov al, byte ptr [si + 0x47e]
            m.si = m.rw(m.bp +% 0x0006); // 4E56 mov si, word ptr [bp + 6]
            m.setBl(m.rb(m.di +% 0x9EF6)); // 4E59 mov bl, byte ptr [di - 0x610a]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 4E5D sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 4E5F mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.bl(), m.al()); // 4E63 test bl, al
            if (m.zf) continue :sw 0x4E6E; // 4E65 je 0x4e6e
            m.wb(m.bp +% 0xFFFA, 0x1); // 4E67 mov byte ptr [bp - 6], 1
            continue :sw 0x4E74; // 4E6B jmp 0x4e74
        },
        0x4E6E => {
            m.bx = m.dx; // 4E6E mov bx, dx
            m.dx = m.inc(u16, m.dx); // 4E70 inc dx
            m.wb(m.bx, 0x9); // 4E71 mov byte ptr [bx], 9
            continue :sw 0x4E74; // falls through
        },
        0x4E74 => {
            m.cmp(u8, m.rb(m.si +% 0xA51C), 0x0); // 4E74 cmp byte ptr [si - 0x5ae4], 0
            if (!m.zf) continue :sw 0x4E7E; // 4E79 jne 0x4e7e
            continue :sw 0x4F16; // 4E7B jmp 0x4f16
        },
        0x4E7E => {
            m.cmp(u8, m.rb(m.si +% 0x9EED), 0x1); // 4E7E cmp byte ptr [si - 0x6113], 1
            if (!m.zf) continue :sw 0x4ECA; // 4E83 jne 0x4eca
            m.cmp(u8, m.rb(m.si +% 0xA095), 0x0); // 4E85 cmp byte ptr [si - 0x5f6b], 0
            if (m.zf) continue :sw 0x4EC4; // 4E8A je 0x4ec4
            m.di = m.si; // 4E8C mov di, si
            m.di = m.sub(u16, m.di, 0x9); // 4E8E sub di, 9
            m.setAl(m.rb(m.di +% 0xA09E)); // 4E91 mov al, byte ptr [di - 0x5f62]
            m.cbw(); // 4E95 cbw
            m.bx = m.ax; // 4E96 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // 4E98 mov al, byte ptr [bx + 0x490]
            m.cbw(); // 4E9C cbw
            m.cmp(u16, m.ax, 0x9); // 4E9D cmp ax, 9
            if (m.zf) continue :sw 0x4EC4; // 4EA0 je 0x4ec4
            continue :sw 0x4EA2; // falls through
        },
        0x4EA2 => {
            m.di = m.add(u16, m.di, m.ax); // 4EA2 add di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // 4EA4 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0x4EA2; // 4EA9 je 0x4ea2
            m.setAl(m.rb(m.bx +% 0x047E)); // 4EAB mov al, byte ptr [bx + 0x47e]
            m.setBl(m.rb(m.di +% 0x9EF6)); // 4EAF mov bl, byte ptr [di - 0x610a]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 4EB3 sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 4EB5 mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.bl(), m.al()); // 4EB9 test bl, al
            if (m.zf) continue :sw 0x4EC4; // 4EBB je 0x4ec4
            m.wb(m.bp +% 0xFFF4, 0x1); // 4EBD mov byte ptr [bp - 0xc], 1
            continue :sw 0x4ECA; // 4EC1 jmp 0x4eca
        },
        0x4EC4 => {
            m.bx = m.cx; // 4EC4 mov bx, cx
            m.cx = m.inc(u16, m.cx); // 4EC6 inc cx
            m.wb(m.bx, 0x3); // 4EC7 mov byte ptr [bx], 3
            continue :sw 0x4ECA; // falls through
        },
        0x4ECA => {
            m.cmp(u8, m.rb(m.si +% 0x9EEB), 0x1); // 4ECA cmp byte ptr [si - 0x6115], 1
            if (!m.zf) continue :sw 0x4F16; // 4ECF jne 0x4f16
            m.cmp(u8, m.rb(m.si +% 0xA093), 0x0); // 4ED1 cmp byte ptr [si - 0x5f6d], 0
            if (m.zf) continue :sw 0x4F10; // 4ED6 je 0x4f10
            m.di = m.si; // 4ED8 mov di, si
            m.di = m.sub(u16, m.di, 0xB); // 4EDA sub di, 0xb
            m.setAl(m.rb(m.di +% 0xA09E)); // 4EDD mov al, byte ptr [di - 0x5f62]
            m.cbw(); // 4EE1 cbw
            m.bx = m.ax; // 4EE2 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // 4EE4 mov al, byte ptr [bx + 0x490]
            m.cbw(); // 4EE8 cbw
            m.cmp(u16, m.ax, 0xB); // 4EE9 cmp ax, 0xb
            if (m.zf) continue :sw 0x4F10; // 4EEC je 0x4f10
            continue :sw 0x4EEE; // falls through
        },
        0x4EEE => {
            m.di = m.add(u16, m.di, m.ax); // 4EEE add di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // 4EF0 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0x4EEE; // 4EF5 je 0x4eee
            m.setAl(m.rb(m.bx +% 0x047E)); // 4EF7 mov al, byte ptr [bx + 0x47e]
            m.setBl(m.rb(m.di +% 0x9EF6)); // 4EFB mov bl, byte ptr [di - 0x610a]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 4EFF sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 4F01 mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.bl(), m.al()); // 4F05 test bl, al
            if (m.zf) continue :sw 0x4F10; // 4F07 je 0x4f10
            m.wb(m.bp +% 0xFFF4, 0x1); // 4F09 mov byte ptr [bp - 0xc], 1
            continue :sw 0x4F16; // 4F0D jmp 0x4f16
        },
        0x4F10 => {
            m.bx = m.cx; // 4F10 mov bx, cx
            m.cx = m.inc(u16, m.cx); // 4F12 inc cx
            m.wb(m.bx, 0x3); // 4F13 mov byte ptr [bx], 3
            continue :sw 0x4F16; // falls through
        },
        0x4F16 => {
            m.setAl(m.rb(0xA03A)); // 4F16 mov al, byte ptr [0xa03a]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // 4F19 sub ah, ah
            m.di = m.ax; // 4F1B mov di, ax
            m.bx = m.si; // 4F1D mov bx, si
            m.bx = m.sub(u16, m.bx, m.di); // 4F1F sub bx, di
            m.cmp(u8, m.rb(m.bx +% 0x0A68), m.ah()); // 4F21 cmp byte ptr [bx + 0xa68], ah
            if (m.zf) continue :sw 0x4F64; // 4F25 je 0x4f64
            m.cmp(u8, m.rb(m.di +% 0xA09E), m.ah()); // 4F27 cmp byte ptr [di - 0x5f62], ah
            if (m.zf) continue :sw 0x4F5E; // 4F2B je 0x4f5e
            m.setAl(m.rb(m.di +% 0xA09E)); // 4F2D mov al, byte ptr [di - 0x5f62]
            m.cbw(); // 4F31 cbw
            m.si = m.ax; // 4F32 mov si, ax
            m.setAl(m.rb(m.si +% 0x0490)); // 4F34 mov al, byte ptr [si + 0x490]
            m.cbw(); // 4F38 cbw
            continue :sw 0x4F39; // falls through
        },
        0x4F39 => {
            m.di = m.add(u16, m.di, m.ax); // 4F39 add di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // 4F3B cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0x4F39; // 4F40 je 0x4f39
            m.setAl(m.rb(m.si +% 0x047E)); // 4F42 mov al, byte ptr [si + 0x47e]
            m.si = m.rw(m.bp +% 0x0006); // 4F46 mov si, word ptr [bp + 6]
            m.setBl(m.rb(m.di +% 0x9EF6)); // 4F49 mov bl, byte ptr [di - 0x610a]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 4F4D sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 4F4F mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.bl(), m.al()); // 4F53 test bl, al
            if (m.zf) continue :sw 0x4F5E; // 4F55 je 0x4f5e
            m.wb(m.bp +% 0xFFF4, 0x1); // 4F57 mov byte ptr [bp - 0xc], 1
            continue :sw 0x4F64; // 4F5B jmp 0x4f64
        },
        0x4F5E => {
            m.bx = m.cx; // 4F5E mov bx, cx
            m.cx = m.inc(u16, m.cx); // 4F60 inc cx
            m.wb(m.bx, 0x9); // 4F61 mov byte ptr [bx], 9
            continue :sw 0x4F64; // falls through
        },
        0x4F64 => {
            m.setAl(m.rb(0xA03B)); // 4F64 mov al, byte ptr [0xa03b]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // 4F67 sub ah, ah
            m.di = m.ax; // 4F69 mov di, ax
            m.bx = m.si; // 4F6B mov bx, si
            m.bx = m.sub(u16, m.bx, m.di); // 4F6D sub bx, di
            m.cmp(u8, m.rb(m.bx +% 0x0A68), m.ah()); // 4F6F cmp byte ptr [bx + 0xa68], ah
            if (m.zf) continue :sw 0x4FB2; // 4F73 je 0x4fb2
            m.cmp(u8, m.rb(m.di +% 0xA09E), m.ah()); // 4F75 cmp byte ptr [di - 0x5f62], ah
            if (m.zf) continue :sw 0x4FAC; // 4F79 je 0x4fac
            m.setAl(m.rb(m.di +% 0xA09E)); // 4F7B mov al, byte ptr [di - 0x5f62]
            m.cbw(); // 4F7F cbw
            m.si = m.ax; // 4F80 mov si, ax
            m.setAl(m.rb(m.si +% 0x0490)); // 4F82 mov al, byte ptr [si + 0x490]
            m.cbw(); // 4F86 cbw
            continue :sw 0x4F87; // falls through
        },
        0x4F87 => {
            m.di = m.add(u16, m.di, m.ax); // 4F87 add di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // 4F89 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0x4F87; // 4F8E je 0x4f87
            m.setAl(m.rb(m.si +% 0x047E)); // 4F90 mov al, byte ptr [si + 0x47e]
            m.si = m.rw(m.bp +% 0x0006); // 4F94 mov si, word ptr [bp + 6]
            m.setBl(m.rb(m.di +% 0x9EF6)); // 4F97 mov bl, byte ptr [di - 0x610a]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 4F9B sub bh, bh
            m.setBl(m.rb(m.bx +% 0x0470)); // 4F9D mov bl, byte ptr [bx + 0x470]
            m.@"test"(u8, m.bl(), m.al()); // 4FA1 test bl, al
            if (m.zf) continue :sw 0x4FAC; // 4FA3 je 0x4fac
            m.wb(m.bp +% 0xFFF4, 0x1); // 4FA5 mov byte ptr [bp - 0xc], 1
            continue :sw 0x4FB2; // 4FA9 jmp 0x4fb2
        },
        0x4FAC => {
            m.bx = m.cx; // 4FAC mov bx, cx
            m.cx = m.inc(u16, m.cx); // 4FAE inc cx
            m.wb(m.bx, 0x9); // 4FAF mov byte ptr [bx], 9
            continue :sw 0x4FB2; // falls through
        },
        0x4FB2 => {
            m.setAl(m.sub(u8, m.al(), m.al())); // 4FB2 sub al, al
            m.wb(m.bp +% 0xFFEE, m.al()); // 4FB4 mov byte ptr [bp - 0x12], al
            m.wb(m.bp +% 0xFFFC, m.al()); // 4FB7 mov byte ptr [bp - 4], al
            m.wb(m.bp +% 0xFFF6, m.al()); // 4FBA mov byte ptr [bp - 0xa], al
            m.wb(m.bp +% 0xFFFE, m.al()); // 4FBD mov byte ptr [bp - 2], al
            m.wb(m.bp +% 0xFFF2, m.al()); // 4FC0 mov byte ptr [bp - 0xe], al
            m.di = 0xFFF7; // 4FC3 mov di, 0xfff7
            m.si = m.sub(u16, m.si, 0x9); // 4FC6 sub si, 9
            continue :sw 0x4FC9; // falls through
        },
        0x4FC9 => {
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x1); // 4FC9 cmp byte ptr [si - 0x610a], 1
            if (!m.zf) continue :sw 0x4FDC; // 4FCE jne 0x4fdc
            m.cmp(u8, m.rb(0xA060), 0x3); // 4FD0 cmp byte ptr [0xa060], 3
            if (m.zf) continue :sw 0x4FDA; // 4FD5 je 0x4fda
            continue :sw 0x5050; // 4FD7 jmp 0x5050
        },
        0x4FDA => {
            m.si = m.add(u16, m.si, m.di); // 4FDA add si, di
            continue :sw 0x4FDC; // falls through
        },
        0x4FDC => {
            m.setAl(m.rb(m.si +% 0x9EF6)); // 4FDC mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 4FE0 or al, al
            if (m.zf) continue :sw 0x4FDA; // 4FE2 je 0x4fda
            m.cmp(u8, m.al(), 0x7); // 4FE4 cmp al, 7
            if (m.zf) continue :sw 0x5050; // 4FE6 je 0x5050
            m.cmp(u8, m.al(), 0x3); // 4FE8 cmp al, 3
            if (m.zf) continue :sw 0x5030; // 4FEA je 0x5030
            m.cmp(u8, m.al(), 0xA); // 4FEC cmp al, 0xa
            if (m.zf) continue :sw 0x5000; // 4FEE je 0x5000
            continue :sw 0x4FF0; // falls through
        },
        0x4FF0 => {
            m.cmp(u8, m.al(), 0x5); // 4FF0 cmp al, 5
            if (!m.zf) continue :sw 0x4FF8; // 4FF2 jne 0x4ff8
            continue :sw 0x5218; // 4FF4 jmp 0x5218
        },
        0x4FF8 => {
            m.cmp(u8, m.al(), 0xC); // 4FF8 cmp al, 0xc
            if (!m.zf) continue :sw 0x5050; // 4FFA jne 0x5050
            continue :sw 0x50EA; // 4FFC jmp 0x50ea
        },
        0x5000 => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 5000 cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x501E; // 5005 je 0x501e
            m.push(0x500A);
            run4CEC(m, 0x4CC2); // 5007 call 0x4cc2
            if (m.zf) continue :sw 0x501E; // 500A je 0x501e
            m.cmp(u16, m.ax, m.di); // 500C cmp ax, di
            if (m.zf) continue :sw 0x501E; // 500E je 0x501e
            m.ax = m.neg(u16, m.ax); // 5010 neg ax
            m.cmp(u16, m.ax, m.di); // 5012 cmp ax, di
            if (m.zf) continue :sw 0x501E; // 5014 je 0x501e
            m.wb(m.bp +% 0xFFFA, 0x1); // 5016 mov byte ptr [bp - 6], 1
            continue :sw 0x5050; // 501A jmp 0x5050
        },
        0x501E => {
            m.bx = m.dx; // 501E mov bx, dx
            m.dx = m.inc(u16, m.dx); // 5020 inc dx
            m.wb(m.bx, 0x9); // 5021 mov byte ptr [bx], 9
            continue :sw 0x5024; // falls through
        },
        0x5024 => {
            m.si = m.add(u16, m.si, m.di); // 5024 add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 5026 mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 502A or al, al
            if (m.zf) continue :sw 0x5024; // 502C je 0x5024
            continue :sw 0x4FF8; // 502E jmp 0x4ff8
        },
        0x5030 => {
            m.cmp(u8, m.rb(m.bp +% 0xFFF2), 0x1); // 5030 cmp byte ptr [bp - 0xe], 1
            if (m.zf) continue :sw 0x5050; // 5034 je 0x5050
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 5036 cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x5064; // 503B je 0x5064
            m.push(0x5040);
            run4CEC(m, 0x4C98); // 503D call 0x4c98
            if (m.zf) continue :sw 0x5064; // 5040 je 0x5064
            m.cmp(u16, m.ax, m.di); // 5042 cmp ax, di
            if (m.zf) continue :sw 0x5064; // 5044 je 0x5064
            m.ax = m.neg(u16, m.ax); // 5046 neg ax
            m.cmp(u16, m.ax, m.di); // 5048 cmp ax, di
            if (m.zf) continue :sw 0x5064; // 504A je 0x5064
            m.wb(m.bp +% 0xFFF4, 0x1); // 504C mov byte ptr [bp - 0xc], 1
            continue :sw 0x5050; // falls through
        },
        0x5050 => {
            m.cmp(u16, m.di, 0xFFF7); // 5050 cmp di, -9
            if (m.zf) continue :sw 0x5058; // 5053 je 0x5058
            continue :sw 0x52E6; // 5055 jmp 0x52e6
        },
        0x5058 => {
            m.di = 0xFFF5; // 5058 mov di, 0xfff5
            m.si = m.rw(m.bp +% 0x0006); // 505B mov si, word ptr [bp + 6]
            m.si = m.sub(u16, m.si, 0xB); // 505E sub si, 0xb
            continue :sw 0x4FC9; // 5061 jmp 0x4fc9
        },
        0x5064 => {
            m.bx = m.cx; // 5064 mov bx, cx
            m.cx = m.inc(u16, m.cx); // 5066 inc cx
            m.wb(m.bx, 0x9); // 5067 mov byte ptr [bx], 9
            continue :sw 0x506A; // falls through
        },
        0x506A => {
            m.si = m.add(u16, m.si, m.di); // 506A add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 506C mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 5070 or al, al
            if (m.zf) continue :sw 0x506A; // 5072 je 0x506a
            m.cmp(u8, m.al(), 0xA); // 5074 cmp al, 0xa
            if (m.zf) continue :sw 0x507C; // 5076 je 0x507c
            continue :sw 0x4FF0; // 5078 jmp 0x4ff0
        },
        0x507C => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 507C cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x5098; // 5081 je 0x5098
            m.push(0x5086);
            run4CEC(m, 0x4CC2); // 5083 call 0x4cc2
            if (m.zf) continue :sw 0x5098; // 5086 je 0x5098
            m.cmp(u16, m.ax, m.di); // 5088 cmp ax, di
            if (m.zf) continue :sw 0x5098; // 508A je 0x5098
            m.ax = m.neg(u16, m.ax); // 508C neg ax
            m.cmp(u16, m.ax, m.di); // 508E cmp ax, di
            if (m.zf) continue :sw 0x5098; // 5090 je 0x5098
            m.wb(m.bp +% 0xFFFA, 0x1); // 5092 mov byte ptr [bp - 6], 1
            continue :sw 0x5050; // 5096 jmp 0x5050
        },
        0x5098 => {
            m.bx = m.dx; // 5098 mov bx, dx
            m.dx = m.inc(u16, m.dx); // 509A inc dx
            m.wb(m.bx, 0x9); // 509B mov byte ptr [bx], 9
            continue :sw 0x4FDA; // 509E jmp 0x4fda
        },
        0x50A2 => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 50A2 cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x50BE; // 50A7 je 0x50be
            m.push(0x50AC);
            run4CEC(m, 0x4CC2); // 50A9 call 0x4cc2
            if (m.zf) continue :sw 0x50BE; // 50AC je 0x50be
            m.cmp(u16, m.ax, m.di); // 50AE cmp ax, di
            if (m.zf) continue :sw 0x50BE; // 50B0 je 0x50be
            m.ax = m.neg(u16, m.ax); // 50B2 neg ax
            m.cmp(u16, m.ax, m.di); // 50B4 cmp ax, di
            if (m.zf) continue :sw 0x50BE; // 50B6 je 0x50be
            m.wb(m.bp +% 0xFFFA, 0x1); // 50B8 mov byte ptr [bp - 6], 1
            continue :sw 0x5050; // 50BC jmp 0x5050
        },
        0x50BE => {
            m.wb(m.bp +% 0xFFFE, m.inc(u8, m.rb(m.bp +% 0xFFFE))); // 50BE inc byte ptr [bp - 2]
            continue :sw 0x510C; // 50C1 jmp 0x510c
        },
        0x50EA => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 50EA cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x5108; // 50EF je 0x5108
            m.push(0x50F4);
            run4CEC(m, 0x4CC2); // 50F1 call 0x4cc2
            if (m.zf) continue :sw 0x5108; // 50F4 je 0x5108
            m.cmp(u16, m.ax, m.di); // 50F6 cmp ax, di
            if (m.zf) continue :sw 0x5108; // 50F8 je 0x5108
            m.ax = m.neg(u16, m.ax); // 50FA neg ax
            m.cmp(u16, m.ax, m.di); // 50FC cmp ax, di
            if (m.zf) continue :sw 0x5108; // 50FE je 0x5108
            m.wb(m.bp +% 0xFFFA, 0x1); // 5100 mov byte ptr [bp - 6], 1
            continue :sw 0x5050; // 5104 jmp 0x5050
        },
        0x5108 => {
            m.wb(m.bp +% 0xFFFE, m.add(u8, m.rb(m.bp +% 0xFFFE), 0x10)); // 5108 add byte ptr [bp - 2], 0x10
            continue :sw 0x510C; // falls through
        },
        0x510C => {
            m.si = m.add(u16, m.si, m.di); // 510C add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 510E mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 5112 or al, al
            if (m.zf) continue :sw 0x510C; // 5114 je 0x510c
            m.cmp(u8, m.al(), 0xA); // 5116 cmp al, 0xa
            if (m.zf) continue :sw 0x50A2; // 5118 je 0x50a2
            continue :sw 0x4FF8; // 511A jmp 0x4ff8
        },
        0x51CE => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 51CE cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x51EC; // 51D3 je 0x51ec
            m.push(0x51D8);
            run4CEC(m, 0x4C98); // 51D5 call 0x4c98
            if (m.zf) continue :sw 0x51EC; // 51D8 je 0x51ec
            m.cmp(u16, m.ax, m.di); // 51DA cmp ax, di
            if (m.zf) continue :sw 0x51EC; // 51DC je 0x51ec
            m.ax = m.neg(u16, m.ax); // 51DE neg ax
            m.cmp(u16, m.ax, m.di); // 51E0 cmp ax, di
            if (m.zf) continue :sw 0x51EC; // 51E2 je 0x51ec
            m.wb(m.bp +% 0xFFF4, 0x1); // 51E4 mov byte ptr [bp - 0xc], 1
            continue :sw 0x5050; // 51E8 jmp 0x5050
        },
        0x51EC => {
            m.wb(m.bp +% 0xFFF6, m.inc(u8, m.rb(m.bp +% 0xFFF6))); // 51EC inc byte ptr [bp - 0xa]
            continue :sw 0x5240; // 51EF jmp 0x5240
        },
        0x51F2 => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 51F2 cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x5210; // 51F7 je 0x5210
            m.push(0x51FC);
            run4CEC(m, 0x4CC2); // 51F9 call 0x4cc2
            if (m.zf) continue :sw 0x5210; // 51FC je 0x5210
            m.cmp(u16, m.ax, m.di); // 51FE cmp ax, di
            if (m.zf) continue :sw 0x5210; // 5200 je 0x5210
            m.ax = m.neg(u16, m.ax); // 5202 neg ax
            m.cmp(u16, m.ax, m.di); // 5204 cmp ax, di
            if (m.zf) continue :sw 0x5210; // 5206 je 0x5210
            m.wb(m.bp +% 0xFFFA, 0x1); // 5208 mov byte ptr [bp - 6], 1
            continue :sw 0x5050; // 520C jmp 0x5050
        },
        0x5210 => {
            m.bx = m.dx; // 5210 mov bx, dx
            m.dx = m.inc(u16, m.dx); // 5212 inc dx
            m.wb(m.bx, 0x9); // 5213 mov byte ptr [bx], 9
            continue :sw 0x5240; // 5216 jmp 0x5240
        },
        0x5218 => {
            m.cmp(u8, m.rb(m.bp +% 0xFFF2), 0x1); // 5218 cmp byte ptr [bp - 0xe], 1
            if (m.zf) continue :sw 0x5238; // 521C je 0x5238
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 521E cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x523C; // 5223 je 0x523c
            m.push(0x5228);
            run4CEC(m, 0x4C98); // 5225 call 0x4c98
            if (m.zf) continue :sw 0x523C; // 5228 je 0x523c
            m.cmp(u16, m.ax, m.di); // 522A cmp ax, di
            if (m.zf) continue :sw 0x523C; // 522C je 0x523c
            m.ax = m.neg(u16, m.ax); // 522E neg ax
            m.cmp(u16, m.ax, m.di); // 5230 cmp ax, di
            if (m.zf) continue :sw 0x523C; // 5232 je 0x523c
            m.wb(m.bp +% 0xFFF4, 0x1); // 5234 mov byte ptr [bp - 0xc], 1
            continue :sw 0x5238; // falls through
        },
        0x5238 => {
            continue :sw 0x5050; // 5238 jmp 0x5050
        },
        0x523C => {
            m.wb(m.bp +% 0xFFF6, m.add(u8, m.rb(m.bp +% 0xFFF6), 0x10)); // 523C add byte ptr [bp - 0xa], 0x10
            continue :sw 0x5240; // falls through
        },
        0x5240 => {
            m.si = m.add(u16, m.si, m.di); // 5240 add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 5242 mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 5246 or al, al
            if (m.zf) continue :sw 0x5240; // 5248 je 0x5240
            m.cmp(u8, m.al(), 0x3); // 524A cmp al, 3
            if (m.zf) continue :sw 0x51CE; // 524C je 0x51ce
            m.cmp(u8, m.al(), 0x5); // 524E cmp al, 5
            if (m.zf) continue :sw 0x5218; // 5250 je 0x5218
            m.cmp(u8, m.al(), 0xA); // 5252 cmp al, 0xa
            if (m.zf) continue :sw 0x51F2; // 5254 je 0x51f2
            continue :sw 0x5256; // falls through
        },
        0x5256 => {
            m.cmp(u8, m.al(), 0xC); // 5256 cmp al, 0xc
            if (m.zf) continue :sw 0x5288; // 5258 je 0x5288
            continue :sw 0x5050; // 525A jmp 0x5050
        },
        0x525E => {
            m.wb(m.bp +% 0xFFFE, m.inc(u8, m.rb(m.bp +% 0xFFFE))); // 525E inc byte ptr [bp - 2]
            continue :sw 0x52AA; // 5261 jmp 0x52aa
        },
        0x5264 => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 5264 cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x5282; // 5269 je 0x5282
            m.push(0x526E);
            run4CEC(m, 0x4C98); // 526B call 0x4c98
            if (m.zf) continue :sw 0x5282; // 526E je 0x5282
            m.cmp(u16, m.ax, m.di); // 5270 cmp ax, di
            if (m.zf) continue :sw 0x5282; // 5272 je 0x5282
            m.ax = m.neg(u16, m.ax); // 5274 neg ax
            m.cmp(u16, m.ax, m.di); // 5276 cmp ax, di
            if (m.zf) continue :sw 0x5282; // 5278 je 0x5282
            m.wb(m.bp +% 0xFFF4, 0x1); // 527A mov byte ptr [bp - 0xc], 1
            continue :sw 0x5050; // 527E jmp 0x5050
        },
        0x5282 => {
            m.wb(m.bp +% 0xFFF6, m.inc(u8, m.rb(m.bp +% 0xFFF6))); // 5282 inc byte ptr [bp - 0xa]
            continue :sw 0x52AA; // 5285 jmp 0x52aa
        },
        0x5288 => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 5288 cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x52A6; // 528D je 0x52a6
            m.push(0x5292);
            run4CEC(m, 0x4CC2); // 528F call 0x4cc2
            if (m.zf) continue :sw 0x52A6; // 5292 je 0x52a6
            m.cmp(u16, m.ax, m.di); // 5294 cmp ax, di
            if (m.zf) continue :sw 0x52A6; // 5296 je 0x52a6
            m.ax = m.neg(u16, m.ax); // 5298 neg ax
            m.cmp(u16, m.ax, m.di); // 529A cmp ax, di
            if (m.zf) continue :sw 0x52A6; // 529C je 0x52a6
            m.wb(m.bp +% 0xFFFA, 0x1); // 529E mov byte ptr [bp - 6], 1
            continue :sw 0x5050; // 52A2 jmp 0x5050
        },
        0x52A6 => {
            m.wb(m.bp +% 0xFFFE, m.add(u8, m.rb(m.bp +% 0xFFFE), 0x10)); // 52A6 add byte ptr [bp - 2], 0x10
            continue :sw 0x52AA; // falls through
        },
        0x52AA => {
            m.si = m.add(u16, m.si, m.di); // 52AA add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 52AC mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 52B0 or al, al
            if (m.zf) continue :sw 0x52AA; // 52B2 je 0x52aa
            m.cmp(u8, m.al(), 0x3); // 52B4 cmp al, 3
            if (m.zf) continue :sw 0x5264; // 52B6 je 0x5264
            m.cmp(u8, m.al(), 0x5); // 52B8 cmp al, 5
            if (m.zf) continue :sw 0x52C2; // 52BA je 0x52c2
            m.cmp(u8, m.al(), 0xA); // 52BC cmp al, 0xa
            if (m.zf) continue :sw 0x525E; // 52BE je 0x525e
            continue :sw 0x5256; // 52C0 jmp 0x5256
        },
        0x52C2 => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 52C2 cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x52E0; // 52C7 je 0x52e0
            m.push(0x52CC);
            run4CEC(m, 0x4C98); // 52C9 call 0x4c98
            if (m.zf) continue :sw 0x52E0; // 52CC je 0x52e0
            m.cmp(u16, m.ax, m.di); // 52CE cmp ax, di
            if (m.zf) continue :sw 0x52E0; // 52D0 je 0x52e0
            m.ax = m.neg(u16, m.ax); // 52D2 neg ax
            m.cmp(u16, m.ax, m.di); // 52D4 cmp ax, di
            if (m.zf) continue :sw 0x52E0; // 52D6 je 0x52e0
            m.wb(m.bp +% 0xFFF4, 0x1); // 52D8 mov byte ptr [bp - 0xc], 1
            continue :sw 0x5050; // 52DC jmp 0x5050
        },
        0x52E0 => {
            m.wb(m.bp +% 0xFFF6, m.add(u8, m.rb(m.bp +% 0xFFF6), 0x10)); // 52E0 add byte ptr [bp - 0xa], 0x10
            continue :sw 0x52AA; // 52E4 jmp 0x52aa
        },
        0x52E6 => {
            m.cmp(u16, m.di, 0xFFF5); // 52E6 cmp di, -0xb
            if (!m.zf) continue :sw 0x52F0; // 52E9 jne 0x52f0
            m.di = 0x9; // 52EB mov di, 9
            continue :sw 0x52FC; // 52EE jmp 0x52fc
        },
        0x52F0 => {
            m.cmp(u16, m.di, 0x9); // 52F0 cmp di, 9
            if (!m.zf) continue :sw 0x5314; // 52F3 jne 0x5314
            m.di = 0xB; // 52F5 mov di, 0xb
            m.wb(m.bp +% 0xFFF2, 0x0); // 52F8 mov byte ptr [bp - 0xe], 0
            continue :sw 0x52FC; // falls through
        },
        0x52FC => {
            m.si = m.rw(m.bp +% 0x0006); // 52FC mov si, word ptr [bp + 6]
            m.si = m.add(u16, m.si, m.di); // 52FF add si, di
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x8); // 5301 cmp byte ptr [si - 0x610a], 8
            if (m.zf) continue :sw 0x530C; // 5306 je 0x530c
            continue :sw 0x4FDC; // 5308 jmp 0x4fdc
        },
        0x530C => {
            m.wb(m.bp +% 0xFFF2, 0x1); // 530C mov byte ptr [bp - 0xe], 1
            continue :sw 0x4FDA; // 5310 jmp 0x4fda
        },
        0x5314 => {
            m.si = m.rw(m.bp +% 0x0006); // 5314 mov si, word ptr [bp + 6]
            m.wb(m.bp +% 0xFFEC, 0x3); // 5317 mov byte ptr [bp - 0x14], 3
            continue :sw 0x531B; // falls through
        },
        0x531B => {
            m.setBl(m.rb(m.bp +% 0xFFEC)); // 531B mov bl, byte ptr [bp - 0x14]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 531E sub bh, bh
            m.setAl(m.rb(m.bx +% 0x04A6)); // 5320 mov al, byte ptr [bx + 0x4a6]
            m.cbw(); // 5324 cbw
            m.di = m.ax; // 5325 mov di, ax
            continue :sw 0x5327; // falls through
        },
        0x5327 => {
            m.si = m.add(u16, m.si, m.di); // 5327 add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 5329 mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 532D or al, al
            if (m.zf) continue :sw 0x5327; // 532F je 0x5327
            m.cmp(u8, m.al(), 0x7); // 5331 cmp al, 7
            if (m.zf) continue :sw 0x539A; // 5333 je 0x539a
            m.cmp(u8, m.al(), 0x4); // 5335 cmp al, 4
            if (m.zf) continue :sw 0x5380; // 5337 je 0x5380
            m.cmp(u8, m.al(), 0x5); // 5339 cmp al, 5
            if (!m.zf) continue :sw 0x5340; // 533B jne 0x5340
            continue :sw 0x556C; // 533D jmp 0x556c
        },
        0x5340 => {
            m.cmp(u8, m.al(), 0xB); // 5340 cmp al, 0xb
            if (m.zf) continue :sw 0x534C; // 5342 je 0x534c
            continue :sw 0x5344; // falls through
        },
        0x5344 => {
            m.cmp(u8, m.al(), 0xC); // 5344 cmp al, 0xc
            if (!m.zf) continue :sw 0x539A; // 5346 jne 0x539a
            continue :sw 0x543E; // 5348 jmp 0x543e
        },
        0x534C => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 534C cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x536A; // 5351 je 0x536a
            m.push(0x5356);
            run4CEC(m, 0x4CC2); // 5353 call 0x4cc2
            if (m.zf) continue :sw 0x536A; // 5356 je 0x536a
            m.cmp(u16, m.ax, m.di); // 5358 cmp ax, di
            if (m.zf) continue :sw 0x536A; // 535A je 0x536a
            m.ax = m.neg(u16, m.ax); // 535C neg ax
            m.cmp(u16, m.ax, m.di); // 535E cmp ax, di
            if (m.zf) continue :sw 0x536A; // 5360 je 0x536a
            m.wb(m.bp +% 0xFFFA, 0x1); // 5362 mov byte ptr [bp - 6], 1
            continue :sw 0x539A; // 5366 jmp 0x539a
        },
        0x536A => {
            m.bx = m.dx; // 536A mov bx, dx
            m.dx = m.inc(u16, m.dx); // 536C inc dx
            m.wb(m.bx, 0xF); // 536D mov byte ptr [bx], 0xf
            continue :sw 0x5370; // falls through
        },
        0x5370 => {
            m.si = m.add(u16, m.si, m.di); // 5370 add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 5372 mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 5376 or al, al
            if (m.zf) continue :sw 0x5370; // 5378 je 0x5370
            m.cmp(u8, m.al(), 0xB); // 537A cmp al, 0xb
            if (m.zf) continue :sw 0x534C; // 537C je 0x534c
            continue :sw 0x5344; // 537E jmp 0x5344
        },
        0x5380 => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 5380 cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x53AC; // 5385 je 0x53ac
            m.push(0x538A);
            run4CEC(m, 0x4C98); // 5387 call 0x4c98
            if (m.zf) continue :sw 0x53AC; // 538A je 0x53ac
            m.cmp(u16, m.ax, m.di); // 538C cmp ax, di
            if (m.zf) continue :sw 0x53AC; // 538E je 0x53ac
            m.ax = m.neg(u16, m.ax); // 5390 neg ax
            m.cmp(u16, m.ax, m.di); // 5392 cmp ax, di
            if (m.zf) continue :sw 0x53AC; // 5394 je 0x53ac
            m.wb(m.bp +% 0xFFF4, 0x1); // 5396 mov byte ptr [bp - 0xc], 1
            continue :sw 0x539A; // falls through
        },
        0x539A => {
            m.si = m.rw(m.bp +% 0x0006); // 539A mov si, word ptr [bp + 6]
            m.cmp(u8, m.rb(m.bp +% 0xFFEC), 0x0); // 539D cmp byte ptr [bp - 0x14], 0
            if (!m.zf) continue :sw 0x53A6; // 53A1 jne 0x53a6
            continue :sw 0x5654; // 53A3 jmp 0x5654
        },
        0x53A6 => {
            m.wb(m.bp +% 0xFFEC, m.dec(u8, m.rb(m.bp +% 0xFFEC))); // 53A6 dec byte ptr [bp - 0x14]
            continue :sw 0x531B; // 53A9 jmp 0x531b
        },
        0x53AC => {
            m.bx = m.cx; // 53AC mov bx, cx
            m.cx = m.inc(u16, m.cx); // 53AE inc cx
            m.wb(m.bx, 0xF); // 53AF mov byte ptr [bx], 0xf
            continue :sw 0x53B2; // falls through
        },
        0x53B2 => {
            m.si = m.add(u16, m.si, m.di); // 53B2 add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 53B4 mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 53B8 or al, al
            if (m.zf) continue :sw 0x53B2; // 53BA je 0x53b2
            m.cmp(u8, m.al(), 0x4); // 53BC cmp al, 4
            if (m.zf) continue :sw 0x5380; // 53BE je 0x5380
            m.cmp(u8, m.al(), 0xB); // 53C0 cmp al, 0xb
            if (m.zf) continue :sw 0x53D0; // 53C2 je 0x53d0
            m.cmp(u8, m.al(), 0x5); // 53C4 cmp al, 5
            if (m.zf) continue :sw 0x53CC; // 53C6 je 0x53cc
            continue :sw 0x5344; // 53C8 jmp 0x5344
        },
        0x53CC => {
            continue :sw 0x556C; // 53CC jmp 0x556c
        },
        0x53D0 => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 53D0 cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x53EC; // 53D5 je 0x53ec
            m.push(0x53DA);
            run4CEC(m, 0x4CC2); // 53D7 call 0x4cc2
            if (m.zf) continue :sw 0x53EC; // 53DA je 0x53ec
            m.cmp(u16, m.ax, m.di); // 53DC cmp ax, di
            if (m.zf) continue :sw 0x53EC; // 53DE je 0x53ec
            m.ax = m.neg(u16, m.ax); // 53E0 neg ax
            m.cmp(u16, m.ax, m.di); // 53E2 cmp ax, di
            if (m.zf) continue :sw 0x53EC; // 53E4 je 0x53ec
            m.wb(m.bp +% 0xFFFA, 0x1); // 53E6 mov byte ptr [bp - 6], 1
            continue :sw 0x539A; // 53EA jmp 0x539a
        },
        0x53EC => {
            m.bx = m.dx; // 53EC mov bx, dx
            m.dx = m.inc(u16, m.dx); // 53EE inc dx
            m.wb(m.bx, 0xF); // 53EF mov byte ptr [bx], 0xf
            continue :sw 0x5327; // 53F2 jmp 0x5327
        },
        0x53F6 => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 53F6 cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x5412; // 53FB je 0x5412
            m.push(0x5400);
            run4CEC(m, 0x4CC2); // 53FD call 0x4cc2
            if (m.zf) continue :sw 0x5412; // 5400 je 0x5412
            m.cmp(u16, m.ax, m.di); // 5402 cmp ax, di
            if (m.zf) continue :sw 0x5412; // 5404 je 0x5412
            m.ax = m.neg(u16, m.ax); // 5406 neg ax
            m.cmp(u16, m.ax, m.di); // 5408 cmp ax, di
            if (m.zf) continue :sw 0x5412; // 540A je 0x5412
            m.wb(m.bp +% 0xFFFA, 0x1); // 540C mov byte ptr [bp - 6], 1
            continue :sw 0x539A; // 5410 jmp 0x539a
        },
        0x5412 => {
            m.wb(m.bp +% 0xFFFC, m.inc(u8, m.rb(m.bp +% 0xFFFC))); // 5412 inc byte ptr [bp - 4]
            continue :sw 0x5460; // 5415 jmp 0x5460
        },
        0x543E => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 543E cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x545C; // 5443 je 0x545c
            m.push(0x5448);
            run4CEC(m, 0x4CC2); // 5445 call 0x4cc2
            if (m.zf) continue :sw 0x545C; // 5448 je 0x545c
            m.cmp(u16, m.ax, m.di); // 544A cmp ax, di
            if (m.zf) continue :sw 0x545C; // 544C je 0x545c
            m.ax = m.neg(u16, m.ax); // 544E neg ax
            m.cmp(u16, m.ax, m.di); // 5450 cmp ax, di
            if (m.zf) continue :sw 0x545C; // 5452 je 0x545c
            m.wb(m.bp +% 0xFFFA, 0x1); // 5454 mov byte ptr [bp - 6], 1
            continue :sw 0x539A; // 5458 jmp 0x539a
        },
        0x545C => {
            m.wb(m.bp +% 0xFFFC, m.add(u8, m.rb(m.bp +% 0xFFFC), 0x10)); // 545C add byte ptr [bp - 4], 0x10
            continue :sw 0x5460; // falls through
        },
        0x5460 => {
            m.si = m.add(u16, m.si, m.di); // 5460 add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 5462 mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 5466 or al, al
            if (m.zf) continue :sw 0x5460; // 5468 je 0x5460
            m.cmp(u8, m.al(), 0xB); // 546A cmp al, 0xb
            if (m.zf) continue :sw 0x53F6; // 546C je 0x53f6
            continue :sw 0x5344; // 546E jmp 0x5344
        },
        0x5522 => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 5522 cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x5540; // 5527 je 0x5540
            m.push(0x552C);
            run4CEC(m, 0x4C98); // 5529 call 0x4c98
            if (m.zf) continue :sw 0x5540; // 552C je 0x5540
            m.cmp(u16, m.ax, m.di); // 552E cmp ax, di
            if (m.zf) continue :sw 0x5540; // 5530 je 0x5540
            m.ax = m.neg(u16, m.ax); // 5532 neg ax
            m.cmp(u16, m.ax, m.di); // 5534 cmp ax, di
            if (m.zf) continue :sw 0x5540; // 5536 je 0x5540
            m.wb(m.bp +% 0xFFF4, 0x1); // 5538 mov byte ptr [bp - 0xc], 1
            continue :sw 0x539A; // 553C jmp 0x539a
        },
        0x5540 => {
            m.wb(m.bp +% 0xFFEE, m.inc(u8, m.rb(m.bp +% 0xFFEE))); // 5540 inc byte ptr [bp - 0x12]
            continue :sw 0x558E; // 5543 jmp 0x558e
        },
        0x5546 => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 5546 cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x5564; // 554B je 0x5564
            m.push(0x5550);
            run4CEC(m, 0x4CC2); // 554D call 0x4cc2
            if (m.zf) continue :sw 0x5564; // 5550 je 0x5564
            m.cmp(u16, m.ax, m.di); // 5552 cmp ax, di
            if (m.zf) continue :sw 0x5564; // 5554 je 0x5564
            m.ax = m.neg(u16, m.ax); // 5556 neg ax
            m.cmp(u16, m.ax, m.di); // 5558 cmp ax, di
            if (m.zf) continue :sw 0x5564; // 555A je 0x5564
            m.wb(m.bp +% 0xFFFA, 0x1); // 555C mov byte ptr [bp - 6], 1
            continue :sw 0x539A; // 5560 jmp 0x539a
        },
        0x5564 => {
            m.bx = m.dx; // 5564 mov bx, dx
            m.dx = m.inc(u16, m.dx); // 5566 inc dx
            m.wb(m.bx, 0xF); // 5567 mov byte ptr [bx], 0xf
            continue :sw 0x558E; // 556A jmp 0x558e
        },
        0x556C => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 556C cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x558A; // 5571 je 0x558a
            m.push(0x5576);
            run4CEC(m, 0x4C98); // 5573 call 0x4c98
            if (m.zf) continue :sw 0x558A; // 5576 je 0x558a
            m.cmp(u16, m.ax, m.di); // 5578 cmp ax, di
            if (m.zf) continue :sw 0x558A; // 557A je 0x558a
            m.ax = m.neg(u16, m.ax); // 557C neg ax
            m.cmp(u16, m.ax, m.di); // 557E cmp ax, di
            if (m.zf) continue :sw 0x558A; // 5580 je 0x558a
            m.wb(m.bp +% 0xFFF4, 0x1); // 5582 mov byte ptr [bp - 0xc], 1
            continue :sw 0x539A; // 5586 jmp 0x539a
        },
        0x558A => {
            m.wb(m.bp +% 0xFFEE, m.add(u8, m.rb(m.bp +% 0xFFEE), 0x10)); // 558A add byte ptr [bp - 0x12], 0x10
            continue :sw 0x558E; // falls through
        },
        0x558E => {
            m.si = m.add(u16, m.si, m.di); // 558E add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 5590 mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 5594 or al, al
            if (m.zf) continue :sw 0x558E; // 5596 je 0x558e
            m.cmp(u8, m.al(), 0x4); // 5598 cmp al, 4
            if (m.zf) continue :sw 0x5522; // 559A je 0x5522
            m.cmp(u8, m.al(), 0x5); // 559C cmp al, 5
            if (m.zf) continue :sw 0x556C; // 559E je 0x556c
            m.cmp(u8, m.al(), 0xB); // 55A0 cmp al, 0xb
            if (m.zf) continue :sw 0x5546; // 55A2 je 0x5546
            continue :sw 0x55A4; // falls through
        },
        0x55A4 => {
            m.cmp(u8, m.al(), 0xC); // 55A4 cmp al, 0xc
            if (m.zf) continue :sw 0x55F4; // 55A6 je 0x55f4
            continue :sw 0x539A; // 55A8 jmp 0x539a
        },
        0x55AC => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 55AC cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x55CA; // 55B1 je 0x55ca
            m.push(0x55B6);
            run4CEC(m, 0x4CC2); // 55B3 call 0x4cc2
            if (m.zf) continue :sw 0x55CA; // 55B6 je 0x55ca
            m.cmp(u16, m.ax, m.di); // 55B8 cmp ax, di
            if (m.zf) continue :sw 0x55CA; // 55BA je 0x55ca
            m.ax = m.neg(u16, m.ax); // 55BC neg ax
            m.cmp(u16, m.ax, m.di); // 55BE cmp ax, di
            if (m.zf) continue :sw 0x55CA; // 55C0 je 0x55ca
            m.wb(m.bp +% 0xFFFA, 0x1); // 55C2 mov byte ptr [bp - 6], 1
            continue :sw 0x539A; // 55C6 jmp 0x539a
        },
        0x55CA => {
            m.wb(m.bp +% 0xFFFC, m.inc(u8, m.rb(m.bp +% 0xFFFC))); // 55CA inc byte ptr [bp - 4]
            continue :sw 0x5616; // 55CD jmp 0x5616
        },
        0x55D0 => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 55D0 cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x55EE; // 55D5 je 0x55ee
            m.push(0x55DA);
            run4CEC(m, 0x4C98); // 55D7 call 0x4c98
            if (m.zf) continue :sw 0x55EE; // 55DA je 0x55ee
            m.cmp(u16, m.ax, m.di); // 55DC cmp ax, di
            if (m.zf) continue :sw 0x55EE; // 55DE je 0x55ee
            m.ax = m.neg(u16, m.ax); // 55E0 neg ax
            m.cmp(u16, m.ax, m.di); // 55E2 cmp ax, di
            if (m.zf) continue :sw 0x55EE; // 55E4 je 0x55ee
            m.wb(m.bp +% 0xFFF4, 0x1); // 55E6 mov byte ptr [bp - 0xc], 1
            continue :sw 0x539A; // 55EA jmp 0x539a
        },
        0x55EE => {
            m.wb(m.bp +% 0xFFEE, m.inc(u8, m.rb(m.bp +% 0xFFEE))); // 55EE inc byte ptr [bp - 0x12]
            continue :sw 0x5616; // 55F1 jmp 0x5616
        },
        0x55F4 => {
            m.cmp(u8, m.rb(m.si +% 0xA164), 0x0); // 55F4 cmp byte ptr [si - 0x5e9c], 0
            if (m.zf) continue :sw 0x5612; // 55F9 je 0x5612
            m.push(0x55FE);
            run4CEC(m, 0x4CC2); // 55FB call 0x4cc2
            if (m.zf) continue :sw 0x5612; // 55FE je 0x5612
            m.cmp(u16, m.ax, m.di); // 5600 cmp ax, di
            if (m.zf) continue :sw 0x5612; // 5602 je 0x5612
            m.ax = m.neg(u16, m.ax); // 5604 neg ax
            m.cmp(u16, m.ax, m.di); // 5606 cmp ax, di
            if (m.zf) continue :sw 0x5612; // 5608 je 0x5612
            m.wb(m.bp +% 0xFFFA, 0x1); // 560A mov byte ptr [bp - 6], 1
            continue :sw 0x539A; // 560E jmp 0x539a
        },
        0x5612 => {
            m.wb(m.bp +% 0xFFFC, m.add(u8, m.rb(m.bp +% 0xFFFC), 0x10)); // 5612 add byte ptr [bp - 4], 0x10
            continue :sw 0x5616; // falls through
        },
        0x5616 => {
            m.si = m.add(u16, m.si, m.di); // 5616 add si, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // 5618 mov al, byte ptr [si - 0x610a]
            m.setAl(m.@"or"(u8, m.al(), m.al())); // 561C or al, al
            if (m.zf) continue :sw 0x5616; // 561E je 0x5616
            m.cmp(u8, m.al(), 0x4); // 5620 cmp al, 4
            if (m.zf) continue :sw 0x55D0; // 5622 je 0x55d0
            m.cmp(u8, m.al(), 0x5); // 5624 cmp al, 5
            if (m.zf) continue :sw 0x5630; // 5626 je 0x5630
            m.cmp(u8, m.al(), 0xB); // 5628 cmp al, 0xb
            if (m.zf) continue :sw 0x55AC; // 562A je 0x55ac
            continue :sw 0x55A4; // 562C jmp 0x55a4
        },
        0x5630 => {
            m.cmp(u8, m.rb(m.si +% 0xA09E), 0x0); // 5630 cmp byte ptr [si - 0x5f62], 0
            if (m.zf) continue :sw 0x564E; // 5635 je 0x564e
            m.push(0x563A);
            run4CEC(m, 0x4C98); // 5637 call 0x4c98
            if (m.zf) continue :sw 0x564E; // 563A je 0x564e
            m.cmp(u16, m.ax, m.di); // 563C cmp ax, di
            if (m.zf) continue :sw 0x564E; // 563E je 0x564e
            m.ax = m.neg(u16, m.ax); // 5640 neg ax
            m.cmp(u16, m.ax, m.di); // 5642 cmp ax, di
            if (m.zf) continue :sw 0x564E; // 5644 je 0x564e
            m.wb(m.bp +% 0xFFF4, 0x1); // 5646 mov byte ptr [bp - 0xc], 1
            continue :sw 0x539A; // 564A jmp 0x539a
        },
        0x564E => {
            m.wb(m.bp +% 0xFFEE, m.add(u8, m.rb(m.bp +% 0xFFEE), 0x10)); // 564E add byte ptr [bp - 0x12], 0x10
            continue :sw 0x5616; // 5652 jmp 0x5616
        },
        0x5654 => {
            m.cmp(u8, m.rb(m.bp +% 0xFFFE), 0x0); // 5654 cmp byte ptr [bp - 2], 0
            if (!m.zf) continue :sw 0x5660; // 5658 jne 0x5660
            m.cmp(u8, m.rb(m.bp +% 0xFFFC), 0x0); // 565A cmp byte ptr [bp - 4], 0
            if (m.zf) continue :sw 0x56AC; // 565E je 0x56ac
            continue :sw 0x5660; // falls through
        },
        0x5660 => {
            m.@"test"(u8, m.rb(m.bp +% 0xFFFE), 0xF); // 5660 test byte ptr [bp - 2], 0xf
            if (m.zf) continue :sw 0x5676; // 5664 je 0x5676
            m.bx = m.dx; // 5666 mov bx, dx
            m.dx = m.inc(u16, m.dx); // 5668 inc dx
            m.wb(m.bx, 0x1B); // 5669 mov byte ptr [bx], 0x1b
            m.bx = m.dx; // 566C mov bx, dx
            m.dx = m.inc(u16, m.dx); // 566E inc dx
            m.wb(m.bx, 0x9); // 566F mov byte ptr [bx], 9
            m.wb(m.bp +% 0xFFFE, m.sub(u8, m.rb(m.bp +% 0xFFFE), 0x11)); // 5672 sub byte ptr [bp - 2], 0x11
            continue :sw 0x5676; // falls through
        },
        0x5676 => {
            m.setAl(m.rb(m.bp +% 0xFFFC)); // 5676 mov al, byte ptr [bp - 4]
            m.@"test"(u8, m.al(), 0xF); // 5679 test al, 0xf
            if (m.zf) continue :sw 0x569A; // 567B je 0x569a
            m.bx = m.dx; // 567D mov bx, dx
            m.dx = m.inc(u16, m.dx); // 567F inc dx
            m.wb(m.bx, 0x1B); // 5680 mov byte ptr [bx], 0x1b
            m.bx = m.dx; // 5683 mov bx, dx
            m.dx = m.inc(u16, m.dx); // 5685 inc dx
            m.wb(m.bx, 0xF); // 5686 mov byte ptr [bx], 0xf
            m.setAl(m.sub(u8, m.al(), 0x11)); // 5689 sub al, 0x11
            continue :sw 0x5696; // 568B jmp 0x5696
        },
        0x568E => {
            m.bx = m.dx; // 568E mov bx, dx
            m.dx = m.inc(u16, m.dx); // 5690 inc dx
            m.wb(m.bx, 0xF); // 5691 mov byte ptr [bx], 0xf
            m.setAl(m.dec(u8, m.al())); // 5694 dec al
            continue :sw 0x5696; // falls through
        },
        0x5696 => {
            m.@"test"(u8, m.al(), 0xF); // 5696 test al, 0xf
            if (!m.zf) continue :sw 0x568E; // 5698 jne 0x568e
            continue :sw 0x569A; // falls through
        },
        0x569A => {
            m.setAl(m.add(u8, m.al(), m.rb(m.bp +% 0xFFFE))); // 569A add al, byte ptr [bp - 2]
            continue :sw 0x56A8; // 569D jmp 0x56a8
        },
        0x56A0 => {
            m.bx = m.dx; // 56A0 mov bx, dx
            m.dx = m.inc(u16, m.dx); // 56A2 inc dx
            m.wb(m.bx, 0x1B); // 56A3 mov byte ptr [bx], 0x1b
            m.setAl(m.sub(u8, m.al(), 0x10)); // 56A6 sub al, 0x10
            continue :sw 0x56A8; // falls through
        },
        0x56A8 => {
            m.cmp(u8, m.al(), 0x0); // 56A8 cmp al, 0
            if (!m.zf and m.sf == m.of) continue :sw 0x56A0; // 56AA jg 0x56a0
            continue :sw 0x56AC; // falls through
        },
        0x56AC => {
            m.cmp(u8, m.rb(m.bp +% 0xFFF4), 0x0); // 56AC cmp byte ptr [bp - 0xc], 0
            if (!m.zf) continue :sw 0x56C9; // 56B0 jne 0x56c9
            m.setBl(m.rb(0xA051)); // 56B2 mov bl, byte ptr [0xa051]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 56B6 sub bh, bh
            m.bx = m.sub(u16, m.bx, m.si); // 56B8 sub bx, si
            m.bx = m.neg(u16, m.bx); // 56BA neg bx
            m.cmp(u8, m.rb(m.bx +% 0x0CFF), 0x0); // 56BC cmp byte ptr [bx + 0xcff], 0
            if (m.zf) continue :sw 0x56C9; // 56C1 je 0x56c9
            m.bx = m.dx; // 56C3 mov bx, dx
            m.dx = m.inc(u16, m.dx); // 56C5 inc dx
            m.wb(m.bx, 0x1E); // 56C6 mov byte ptr [bx], 0x1e
            continue :sw 0x56C9; // falls through
        },
        0x56C9 => {
            m.bx = m.dx; // 56C9 mov bx, dx
            m.wb(m.bx, 0x0); // 56CB mov byte ptr [bx], 0
            m.cmp(u8, m.rb(m.bp +% 0xFFF6), 0x0); // 56CE cmp byte ptr [bp - 0xa], 0
            if (!m.zf) continue :sw 0x56DA; // 56D2 jne 0x56da
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // 56D4 cmp byte ptr [bp - 0x12], 0
            if (m.zf) continue :sw 0x5726; // 56D8 je 0x5726
            continue :sw 0x56DA; // falls through
        },
        0x56DA => {
            m.@"test"(u8, m.rb(m.bp +% 0xFFF6), 0xF); // 56DA test byte ptr [bp - 0xa], 0xf
            if (m.zf) continue :sw 0x56F0; // 56DE je 0x56f0
            m.bx = m.cx; // 56E0 mov bx, cx
            m.cx = m.inc(u16, m.cx); // 56E2 inc cx
            m.wb(m.bx, 0x1B); // 56E3 mov byte ptr [bx], 0x1b
            m.bx = m.cx; // 56E6 mov bx, cx
            m.cx = m.inc(u16, m.cx); // 56E8 inc cx
            m.wb(m.bx, 0x9); // 56E9 mov byte ptr [bx], 9
            m.wb(m.bp +% 0xFFF6, m.sub(u8, m.rb(m.bp +% 0xFFF6), 0x11)); // 56EC sub byte ptr [bp - 0xa], 0x11
            continue :sw 0x56F0; // falls through
        },
        0x56F0 => {
            m.setAl(m.rb(m.bp +% 0xFFEE)); // 56F0 mov al, byte ptr [bp - 0x12]
            m.@"test"(u8, m.al(), 0xF); // 56F3 test al, 0xf
            if (m.zf) continue :sw 0x5714; // 56F5 je 0x5714
            m.bx = m.cx; // 56F7 mov bx, cx
            m.cx = m.inc(u16, m.cx); // 56F9 inc cx
            m.wb(m.bx, 0x1B); // 56FA mov byte ptr [bx], 0x1b
            m.bx = m.cx; // 56FD mov bx, cx
            m.cx = m.inc(u16, m.cx); // 56FF inc cx
            m.wb(m.bx, 0xF); // 5700 mov byte ptr [bx], 0xf
            m.setAl(m.sub(u8, m.al(), 0x11)); // 5703 sub al, 0x11
            continue :sw 0x5710; // 5705 jmp 0x5710
        },
        0x5708 => {
            m.bx = m.cx; // 5708 mov bx, cx
            m.cx = m.inc(u16, m.cx); // 570A inc cx
            m.wb(m.bx, 0xF); // 570B mov byte ptr [bx], 0xf
            m.setAl(m.dec(u8, m.al())); // 570E dec al
            continue :sw 0x5710; // falls through
        },
        0x5710 => {
            m.@"test"(u8, m.al(), 0xF); // 5710 test al, 0xf
            if (!m.zf) continue :sw 0x5708; // 5712 jne 0x5708
            continue :sw 0x5714; // falls through
        },
        0x5714 => {
            m.setAl(m.add(u8, m.al(), m.rb(m.bp +% 0xFFF6))); // 5714 add al, byte ptr [bp - 0xa]
            continue :sw 0x5722; // 5717 jmp 0x5722
        },
        0x571A => {
            m.bx = m.cx; // 571A mov bx, cx
            m.cx = m.inc(u16, m.cx); // 571C inc cx
            m.wb(m.bx, 0x1B); // 571D mov byte ptr [bx], 0x1b
            m.setAl(m.sub(u8, m.al(), 0x10)); // 5720 sub al, 0x10
            continue :sw 0x5722; // falls through
        },
        0x5722 => {
            m.cmp(u8, m.al(), 0x0); // 5722 cmp al, 0
            if (!m.zf and m.sf == m.of) continue :sw 0x571A; // 5724 jg 0x571a
            continue :sw 0x5726; // falls through
        },
        0x5726 => {
            m.cmp(u8, m.rb(m.bp +% 0xFFFA), 0x0); // 5726 cmp byte ptr [bp - 6], 0
            if (!m.zf) continue :sw 0x5743; // 572A jne 0x5743
            m.setBl(m.rb(0xA041)); // 572C mov bl, byte ptr [0xa041]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // 5730 sub bh, bh
            m.bx = m.sub(u16, m.bx, m.si); // 5732 sub bx, si
            m.bx = m.neg(u16, m.bx); // 5734 neg bx
            m.cmp(u8, m.rb(m.bx +% 0x0CFF), 0x0); // 5736 cmp byte ptr [bx + 0xcff], 0
            if (m.zf) continue :sw 0x5743; // 573B je 0x5743
            m.bx = m.cx; // 573D mov bx, cx
            m.cx = m.inc(u16, m.cx); // 573F inc cx
            m.wb(m.bx, 0x1E); // 5740 mov byte ptr [bx], 0x1e
            continue :sw 0x5743; // falls through
        },
        0x5743 => {
            m.bx = m.cx; // 5743 mov bx, cx
            m.wb(m.bx, 0x0); // 5745 mov byte ptr [bx], 0
            m.di = m.sub(u16, m.di, m.di); // 5748 sub di, di
            m.bx = 0x70E5; // 574A mov bx, 0x70e5
            m.bp = 0xB4E6; // 574D mov bp, 0xb4e6
            continue :sw 0x5769; // 5750 jmp 0x5769
        },
        0x5752 => {
            m.setAl(m.rb(m.bx +% m.di)); // 5752 mov al, byte ptr [bx + di]
            m.setAl(m.sub(u8, m.al(), m.rb(m.di +% 0x9FEC))); // 5754 sub al, byte ptr [di - 0x6014]
            m.wb(m.bp +% m.di, m.al()); // 5758 mov byte ptr [bp + di], al
            m.cmp(u8, m.rb(m.di +% 0x9FED), 0x0); // 575A cmp byte ptr [di - 0x6013], 0
            if (m.zf) continue :sw 0x5779; // 575F je 0x5779
            m.setAl(m.add(u8, m.al(), m.rb(m.di +% 0xA060))); // 5761 add al, byte ptr [di - 0x5fa0]
            m.wb(m.bx +% m.di +% 0x0001, m.al()); // 5765 mov byte ptr [bx + di + 1], al
            m.di = m.inc(u16, m.di); // 5768 inc di
            continue :sw 0x5769; // falls through
        },
        0x5769 => {
            m.cmp(u16, m.di, 0xA); // 5769 cmp di, 0xa
            if (m.sf == m.of) continue :sw 0x5779; // 576C jge 0x5779
            m.cmp(u8, m.rb(m.di +% 0xA060), 0x0); // 576E cmp byte ptr [di - 0x5fa0], 0
            if (!m.zf) continue :sw 0x5752; // 5773 jne 0x5752
            m.setAl(m.rb(m.bx +% m.di)); // 5775 mov al, byte ptr [bx + di]
            m.wb(m.bp +% m.di, m.al()); // 5777 mov byte ptr [bp + di], al
            continue :sw 0x5779; // falls through
        },
        0x5779 => {
            m.setAl(0xE5); // 5779 mov al, 0xe5
            m.si = m.sub(u16, m.si, m.si); // 577B sub si, si
            m.dx = m.si; // 577D mov dx, si
            continue :sw 0x578B; // 577F jmp 0x578b
        },
        0x5782 => {
            m.cmp(u8, m.rb(m.bp +% m.si), m.al()); // 5782 cmp byte ptr [bp + si], al
            if (m.zf or m.sf != m.of) continue :sw 0x578A; // 5784 jle 0x578a
            m.setAl(m.rb(m.bp +% m.si)); // 5786 mov al, byte ptr [bp + si]
            m.dx = m.si; // 5788 mov dx, si
            continue :sw 0x578A; // falls through
        },
        0x578A => {
            m.si = m.inc(u16, m.si); // 578A inc si
            continue :sw 0x578B; // falls through
        },
        0x578B => {
            m.cmp(u16, m.si, m.di); // 578B cmp si, di
            if (m.zf or m.sf != m.of) continue :sw 0x5782; // 578D jle 0x5782
            m.di = m.dx; // 578F mov di, dx
            continue :sw 0x579B; // 5791 jmp 0x579b
        },
        0x5794 => {
            m.cmp(u8, m.rb(m.bx +% m.di), m.al()); // 5794 cmp byte ptr [bx + di], al
            if (m.sf == m.of) continue :sw 0x579A; // 5796 jge 0x579a
            m.setAl(m.rb(m.bx +% m.di)); // 5798 mov al, byte ptr [bx + di]
            continue :sw 0x579A; // falls through
        },
        0x579A => {
            m.di = m.dec(u16, m.di); // 579A dec di
            continue :sw 0x579B; // falls through
        },
        0x579B => {
            m.di = m.@"or"(u16, m.di, m.di); // 579B or di, di
            if (m.sf == m.of) continue :sw 0x5794; // 579D jge 0x5794
            m.cbw(); // 579F cbw
            continue :sw 0x57A0; // falls through
        },
        0x57A0 => {
            m.dx = m.pop(); // 57A0 pop dx
            m.cx = m.pop(); // 57A1 pop cx
            m.bx = m.pop(); // 57A2 pop bx
            m.si = m.pop(); // 57A3 pop si
            m.di = m.pop(); // 57A4 pop di
            m.sp = m.add(u16, m.sp, 0x1C); // 57A5 add sp, 0x1c
            m.bp = m.pop(); // 57A8 pop bp
            return; // 57A9 retf 4
        },
        else => unreachable,
    }
}

pub const entry_a026: u16 = 0xA026;
pub const entry_cd20: u16 = 0xCD20;

/// The labels of A026 that call `m.mark` (all but the entry).
pub const labels_a026 = [_]u16{
    0xA054,
    0xA066,
    0xA080,
    0xA08F,
    0xA097,
    0xA0A4,
    0xA0AD,
    0xA0B8,
    0xA0BB,
    0xA0C8,
    0xA0DB,
    0xA0EC,
    0xA0FB,
    0xA10A,
    0xA10C,
    0xA11A,
    0xA11D,
    0xA13C,
    0xA147,
    0xA151,
    0xA154,
    0xA166,
    0xA16A,
    0xA182,
    0xA19A,
    0xA1AA,
    0xA1CA,
    0xA1D9,
    0xA1DE,
    0xA1EE,
    0xA1F8,
    0xA1FB,
    0xA208,
    0xA218,
    0xA246,
    0xA255,
    0xA272,
    0xA288,
    0xA28D,
    0xA29A,
    0xA2A5,
    0xA2C1,
    0xA2D8,
    0xA2E8,
    0xA304,
    0xA31B,
    0xA33D,
    0xA354,
    0xA376,
    0xA389,
    0xA393,
    0xA39A,
    0xA3A5,
    0xA3AD,
    0xA3B5,
    0xA3C9,
    0xA3D4,
    0xA3D6,
    0xA3E5,
    0xA401,
    0xA414,
    0xA424,
    0xA42C,
    0xA434,
    0xA43C,
    0xA446,
    0xA450,
    0xA456,
    0xA457,
    0xA468,
    0xA47E,
    0xA488,
    0xA49A,
    0xA4AD,
    0xA4B8,
    0xA4C1,
    0xA4CC,
    0xA4D0,
    0xA4D8,
    0xA4F0,
    0xA514,
    0xA51C,
    0xA52D,
    0xA54B,
    0xA54F,
    0xA55B,
    0xA55E,
    0xA563,
    0xA56C,
    0xA57C,
    0xA57D,
    0xA58C,
    0xA5A0,
    0xA5A4,
    0xA5AE,
    0xA5B4,
    0xA5B5,
    0xA5C0,
    0xA5C8,
    0xA5DC,
    0xA5E6,
    0xA5E8,
    0xA5F7,
    0xA613,
    0xA626,
    0xA636,
    0xA63E,
    0xA64B,
    0xA655,
    0xA65F,
    0xA664,
    0xA665,
    0xA676,
    0xA68C,
    0xA696,
    0xA6AB,
    0xA6B4,
    0xA6C5,
    0xA6CF,
    0xA6F3,
    0xA6FC,
    0xA70D,
    0xA72B,
    0xA72F,
    0xA73B,
    0xA73E,
    0xA746,
    0xA74F,
    0xA75E,
    0xA75F,
    0xA76E,
    0xA782,
    0xA786,
    0xA790,
    0xA796,
    0xA797,
    0xA79E,
    0xA7A6,
    0xA7AE,
    0xA7C1,
    0xA7D0,
    0xA7E3,
    0xA7EF,
    0xA7F1,
    0xA803,
    0xA807,
    0xA80F,
    0xA817,
    0xA827,
    0xA837,
    0xA84B,
    0xA862,
    0xA86D,
    0xA877,
    0xA87A,
    0xA884,
    0xA886,
    0xA892,
    0xA89E,
    0xA8AE,
    0xA8C2,
    0xA8D9,
    0xA8E4,
    0xA8EE,
    0xA8F0,
    0xA900,
    0xA914,
    0xA918,
    0xA930,
    0xA93A,
    0xA941,
    0xA96F,
    0xA97E,
    0xA998,
    0xA9AE,
    0xA9B3,
    0xA9CC,
    0xA9DF,
    0xA9E9,
    0xA9EB,
    0xA9F5,
    0xA9FD,
    0xAA06,
    0xAA20,
    0xAA3A,
    0xAA4B,
    0xAA55,
    0xAA5C,
    0xAA6D,
    0xAA77,
    0xAA87,
    0xAA96,
    0xAA9A,
    0xAAA9,
    0xAAAC,
    0xAAC6,
    0xAAC8,
    0xAADA,
    0xAAF5,
    0xAAF8,
    0xAAFF,
    0xAB0E,
    0xAB12,
    0xAB2B,
    0xAB46,
    0xAB52,
    0xAB57,
    0xAB5C,
    0xAB60,
    0xAB6F,
    0xAB79,
    0xAB80,
    0xAB8F,
    0xAB94,
    0xAB9B,
    0xABAA,
    0xABBB,
    0xABC6,
    0xABC7,
    0xABCE,
    0xABD8,
    0xABE3,
    0xABEF,
    0xABF8,
    0xAC00,
    0xAC06,
    0xAC07,
    0xAC10,
    0xAC34,
    0xAC37,
    0xAC59,
    0xAC5E,
    0xAC6A,
    0xAC8A,
    0xAC99,
    0xAC9E,
    0xACAA,
    0xACCA,
    0xACD9,
    0xACDE,
    0xACEC,
    0xACF6,
    0xAD00,
    0xAD0D,
    0xAD0F,
    0xAD3A,
    0xAD49,
    0xAD4E,
    0xAD50,
    0xAD7A,
    0xAD7E,
    0xAD84,
    0xAD88,
    0xAD8C,
    0xAD90,
    0xAD97,
    0xAD9E,
    0xADBD,
    0xADCC,
    0xADD7,
    0xAE14,
    0xAE26,
    0xAE2A,
    0xAE34,
    0xAE3E,
    0xAE63,
    0xAE73,
    0xAE7E,
    0xAE86,
    0xAE90,
    0xAE98,
    0xAEAD,
    0xAEF8,
    0xAEFC,
    0xAF05,
    0xAF1A,
    0xAF8D,
    0xAF90,
    0xAF98,
    0xAFDE,
    0xAFE6,
    0xAFF6,
    0xAFFB,
    0xB000,
    0xB004,
    0xB019,
    0xB02F,
    0xB053,
    0xB05A,
    0xB05C,
    0xB06E,
    0xB072,
    0xB080,
    0xB083,
    0xB0A7,
    0xB0BC,
    0xB0CA,
    0xB0CC,
    0xB0E0,
    0xB0EB,
    0xB0F2,
    0xB0F8,
    0xB0FC,
    0xB11C,
    0xB122,
    0xB125,
    0xB13D,
    0xB14F,
    0xB156,
    0xB15C,
    0xB15D,
    0xB175,
    0xB17C,
    0xB182,
    0xB183,
    0xB19C,
    0xB1A2,
    0xB1A5,
    0xB1BE,
    0xB1C2,
    0xB1F0,
    0xB1F6,
    0xB216,
    0xB219,
    0xB21D,
    0xB226,
    0xB239,
    0xB242,
    0xB24A,
    0xB250,
    0xB263,
    0xB268,
    0xB277,
    0xB291,
    0xB29C,
    0xB2AB,
    0xB2C8,
    0xB2CE,
    0xB2DD,
    0xB2E0,
    0xB2FD,
    0xB308,
    0xB317,
    0xB318,
    0xB335,
    0xB33A,
    0xB349,
    0xB34A,
    0xB367,
    0xB370,
    0xB376,
    0xB385,
    0xB388,
    0xB3A5,
    0xB3AA,
    0xB3B9,
    0xB3BC,
    0xB3CD,
    0xB3DC,
    0xB3E0,
    0xB415,
    0xB424,
    0xB42D,
    0xB437,
    0xB445,
    0xB470,
    0xB47C,
    0xB483,
    0xB48E,
    0xB498,
    0xB49F,
    0xB4B1,
    0xB4BA,
    0xB4EB,
    0xB4F0,
    0xB4F8,
    0xB506,
    0xB50C,
    0xB50F,
    0xB521,
    0xB524,
    0xB52B,
    0xB53C,
    0xB542,
    0xB545,
    0xB55A,
    0xB560,
    0xB563,
    0xB578,
    0xB57E,
    0xB581,
    0xB593,
    0xB598,
    0xB5A7,
    0xB5AA,
    0xB5B5,
    0xB5B8,
    0xB5C0,
    0xB5CA,
    0xB5D4,
    0xB5DF,
    0xB5E8,
    0xB5F0,
    0xB627,
    0xB62E,
    0xB630,
    0xB642,
    0xB646,
    0xB656,
    0xB659,
    0xB672,
    0xB692,
    0xB694,
    0xB6AF,
    0xB6BA,
    0xB6C6,
    0xB6CA,
    0xB6E4,
    0xB6E7,
    0xB704,
    0xB70A,
    0xB70E,
    0xB730,
    0xB738,
    0xB75A,
    0xB769,
    0xB777,
    0xB780,
    0xB799,
    0xB7A4,
    0xB7B3,
    0xB7B6,
    0xB7D3,
    0xB7D8,
    0xB7E7,
    0xB7E8,
    0xB805,
    0xB80C,
    0xB819,
    0xB833,
    0xB838,
    0xB847,
    0xB861,
    0xB87C,
    0xB889,
    0xB88E,
    0xB893,
    0xB8A2,
    0xB8AB,
    0xB8B5,
    0xB8C3,
    0xB8F0,
    0xB8FA,
    0xB906,
    0xB910,
    0xB91A,
    0xB94B,
    0xB950,
    0xB958,
    0xB966,
    0xB96C,
    0xB96F,
    0xB981,
    0xB984,
    0xB98B,
    0xB99C,
    0xB9A2,
    0xB9A5,
    0xB9BA,
    0xB9C0,
    0xB9C3,
    0xB9D8,
    0xB9DE,
    0xB9E1,
    0xB9F3,
    0xB9F8,
    0xBA07,
    0xBA0A,
    0xBA15,
    0xBA18,
    0xBA20,
    0xBA2A,
    0xBA34,
    0xBA3F,
    0xBA48,
    0xBA50,
    0xBA87,
    0xBA8E,
    0xBA90,
    0xBAA2,
    0xBAA6,
    0xBAB6,
    0xBAB9,
    0xBAD2,
    0xBAF2,
    0xBAF4,
    0xBB0F,
    0xBB1A,
    0xBB26,
    0xBB2A,
    0xBB44,
    0xBB47,
    0xBB64,
    0xBB6A,
    0xBB6E,
    0xBB90,
    0xBB98,
    0xBBBA,
    0xBBC9,
    0xBBD7,
    0xBBE0,
    0xBBF9,
    0xBC04,
    0xBC13,
    0xBC16,
    0xBC33,
    0xBC38,
    0xBC47,
    0xBC48,
    0xBC65,
    0xBC6C,
    0xBC79,
    0xBC93,
    0xBC98,
    0xBCA7,
    0xBCC1,
    0xBCDC,
    0xBCE9,
    0xBCEE,
    0xBCF3,
    0xBD02,
    0xBD0B,
    0xBD20,
    0xBD4F,
    0xBD5E,
    0xBD6B,
    0xBD78,
    0xBD7B,
    0xBD89,
    0xBD96,
    0xBDAF,
    0xBDB6,
    0xBDC0,
    0xBE41,
    0xBE44,
    0xBE74,
    0xBE81,
    0xBE90,
    0xBE94,
    0xBEC0,
    0xBECE,
    0xBEDD,
    0xBEE1,
    0xBF08,
    0xBF34,
    0xBF48,
    0xBF57,
    0xBF5B,
    0xBF82,
    0xBFAE,
    0xBFC2,
    0xBFD1,
    0xBFD5,
    0xBFFC,
    0xC028,
    0xC03C,
    0xC04B,
    0xC04F,
    0xC076,
    0xC0A2,
    0xC0B6,
    0xC0C5,
    0xC0C9,
    0xC0F0,
    0xC11C,
    0xC130,
    0xC13F,
    0xC143,
    0xC152,
    0xC17A,
    0xC1A6,
    0xC1BA,
    0xC1C9,
    0xC1CD,
    0xC1F4,
    0xC220,
    0xC234,
    0xC243,
    0xC247,
    0xC25A,
    0xC26A,
    0xC26E,
    0xC278,
    0xC28D,
    0xC2BC,
    0xC2CB,
    0xC2D8,
    0xC2E6,
    0xC2E9,
    0xC2F7,
    0xC304,
    0xC31D,
    0xC324,
    0xC32E,
    0xC3AF,
    0xC3B2,
    0xC3E2,
    0xC3EF,
    0xC3FE,
    0xC402,
    0xC42E,
    0xC43C,
    0xC44B,
    0xC44F,
    0xC476,
    0xC4A2,
    0xC4B6,
    0xC4C5,
    0xC4C9,
    0xC4F0,
    0xC51C,
    0xC530,
    0xC53F,
    0xC543,
    0xC56A,
    0xC596,
    0xC5AA,
    0xC5B9,
    0xC5BD,
    0xC5E4,
    0xC610,
    0xC624,
    0xC633,
    0xC637,
    0xC65E,
    0xC68A,
    0xC69E,
    0xC6AD,
    0xC6B1,
    0xC6C0,
    0xC6E8,
    0xC714,
    0xC728,
    0xC737,
    0xC73B,
    0xC762,
    0xC78E,
    0xC7A2,
    0xC7B1,
    0xC7B5,
    0xC7C8,
    0xC7D8,
    0xC7DC,
    0xC7E6,
    0xC7F4,
    0xC81C,
    0xC820,
    0xC830,
    0xC835,
    0xC83E,
    0xC84D,
    0xC85A,
    0xC866,
    0xC869,
    0xC877,
    0xC884,
    0xC899,
    0xC8AA,
    0xC8AC,
    0xC8DA,
    0xC8E4,
    0xC925,
    0xC934,
    0xC93F,
    0xC942,
    0xC94C,
    0xC95B,
    0xC95E,
    0xC976,
    0xC985,
    0xC98A,
    0xC999,
    0xC99C,
    0xC9B4,
    0xC9C3,
    0xC9CA,
    0xC9D9,
    0xC9FA,
    0xCA00,
    0xCA0F,
    0xCA30,
    0xCA47,
    0xCA4C,
    0xCA5B,
    0xCA70,
    0xCA9B,
    0xCAAA,
    0xCAB7,
    0xCAC4,
    0xCAC7,
    0xCAD5,
    0xCADE,
    0xCAF3,
    0xCB04,
    0xCB06,
    0xCB34,
    0xCB3E,
    0xCB7F,
    0xCB8E,
    0xCB99,
    0xCB9C,
    0xCBA6,
    0xCBB5,
    0xCBB8,
    0xCBD0,
    0xCBDF,
    0xCBE4,
    0xCBF3,
    0xCBF6,
    0xCC0E,
    0xCC1D,
    0xCC24,
    0xCC33,
    0xCC54,
    0xCC5A,
    0xCC69,
    0xCC8A,
    0xCCA1,
    0xCCA6,
    0xCCC9,
    0xCCDC,
    0xCCEA,
    0xCCF4,
    0xCCFD,
    0xCD1A,
};

/// The labels of CD20 that call `m.mark` (all but the entry).
pub const labels_cd20 = [_]u16{
    0xCD4E,
    0xCD60,
    0xCD7A,
    0xCD89,
    0xCD91,
    0xCD9E,
    0xCDA7,
    0xCDB2,
    0xCDB5,
    0xCDC9,
    0xCDDC,
    0xCDED,
    0xCDFC,
    0xCE0B,
    0xCE0E,
    0xCE1C,
    0xCE1F,
    0xCE3E,
    0xCE49,
    0xCE53,
    0xCE56,
    0xCE68,
    0xCE6C,
    0xCE84,
    0xCE9C,
    0xCEAC,
    0xCECC,
    0xCEDB,
    0xCEE0,
    0xCEF0,
    0xCEFA,
    0xCEFD,
    0xCF11,
    0xCF21,
    0xCF4E,
    0xCF5D,
    0xCF7A,
    0xCF90,
    0xCF95,
    0xCFA2,
    0xCFAD,
    0xCFC9,
    0xCFE0,
    0xCFF0,
    0xD00C,
    0xD023,
    0xD046,
    0xD05D,
    0xD080,
    0xD093,
    0xD09D,
    0xD0A4,
    0xD0AF,
    0xD0B7,
    0xD0BF,
    0xD0DA,
    0xD0EA,
    0xD0EC,
    0xD0FB,
    0xD117,
    0xD12A,
    0xD13A,
    0xD142,
    0xD14A,
    0xD152,
    0xD15C,
    0xD162,
    0xD163,
    0xD174,
    0xD18A,
    0xD194,
    0xD1A6,
    0xD1B9,
    0xD1C4,
    0xD1CD,
    0xD1D8,
    0xD1DC,
    0xD1E4,
    0xD1F5,
    0xD219,
    0xD222,
    0xD237,
    0xD23A,
    0xD258,
    0xD25C,
    0xD268,
    0xD26C,
    0xD271,
    0xD27A,
    0xD28A,
    0xD28B,
    0xD29A,
    0xD2AE,
    0xD2B2,
    0xD2BC,
    0xD2C2,
    0xD2C3,
    0xD2CE,
    0xD2D6,
    0xD2F1,
    0xD300,
    0xD302,
    0xD311,
    0xD32D,
    0xD340,
    0xD350,
    0xD358,
    0xD365,
    0xD36F,
    0xD374,
    0xD375,
    0xD386,
    0xD39C,
    0xD3A6,
    0xD3BB,
    0xD3C4,
    0xD3D5,
    0xD3D8,
    0xD3FC,
    0xD406,
    0xD41B,
    0xD41E,
    0xD43C,
    0xD440,
    0xD44C,
    0xD450,
    0xD458,
    0xD461,
    0xD470,
    0xD471,
    0xD480,
    0xD494,
    0xD498,
    0xD4A2,
    0xD4A8,
    0xD4A9,
    0xD4B0,
    0xD4B8,
    0xD4C0,
    0xD4D3,
    0xD4E2,
    0xD4F5,
    0xD501,
    0xD503,
    0xD515,
    0xD519,
    0xD521,
    0xD529,
    0xD53C,
    0xD53D,
    0xD54C,
    0xD560,
    0xD577,
    0xD582,
    0xD58C,
    0xD590,
    0xD59A,
    0xD5A0,
    0xD5A1,
    0xD5AC,
    0xD5B8,
    0xD5C8,
    0xD5DC,
    0xD5F3,
    0xD5FE,
    0xD608,
    0xD60A,
    0xD61A,
    0xD62E,
    0xD632,
    0xD64A,
    0xD65B,
    0xD666,
    0xD694,
    0xD6A3,
    0xD6BC,
    0xD6D2,
    0xD6D7,
    0xD6F0,
    0xD704,
    0xD706,
    0xD710,
    0xD718,
    0xD720,
    0xD73A,
    0xD745,
    0xD760,
    0xD771,
    0xD782,
    0xD78D,
    0xD79E,
    0xD7A8,
    0xD7B8,
    0xD7C7,
    0xD7CA,
    0xD7D9,
    0xD7DC,
    0xD7FC,
    0xD7FE,
    0xD810,
    0xD82B,
    0xD82E,
    0xD838,
    0xD847,
    0xD84A,
    0xD853,
    0xD86A,
    0xD86C,
    0xD887,
    0xD893,
    0xD898,
    0xD89D,
    0xD8A0,
    0xD8AF,
    0xD8BC,
    0xD8C3,
    0xD8D2,
    0xD8D7,
    0xD8DE,
    0xD8E6,
    0xD8F0,
    0xD8FE,
    0xD908,
    0xD912,
    0xD91E,
    0xD91F,
    0xD926,
    0xD930,
    0xD93B,
    0xD947,
    0xD950,
    0xD958,
    0xD95E,
    0xD95F,
    0xD968,
    0xD984,
    0xD987,
    0xD9A9,
    0xD9AE,
    0xD9BA,
    0xD9DA,
    0xD9E9,
    0xD9EE,
    0xD9FA,
    0xDA1A,
    0xDA29,
    0xDA2E,
    0xDA3C,
    0xDA46,
    0xDA50,
    0xDA64,
    0xDA66,
    0xDA92,
    0xDAA1,
    0xDAA6,
    0xDAA8,
    0xDAD2,
    0xDAD6,
    0xDADC,
    0xDAE0,
    0xDAE4,
    0xDAE8,
    0xDAEF,
    0xDAF6,
    0xDB15,
    0xDB24,
    0xDB2F,
    0xDB6C,
    0xDB7E,
    0xDB82,
    0xDB8C,
    0xDB96,
    0xDBBB,
    0xDBCB,
    0xDBD6,
    0xDBDE,
    0xDBE8,
    0xDBF0,
    0xDC05,
    0xDC50,
    0xDC54,
    0xDC5D,
    0xDC72,
    0xDCE5,
    0xDCE8,
    0xDCF0,
    0xDD36,
    0xDD3E,
    0xDD4E,
    0xDD53,
    0xDD58,
    0xDD5C,
    0xDD71,
    0xDD87,
    0xDDAB,
    0xDDB2,
    0xDDB4,
    0xDDC6,
    0xDDCA,
    0xDDD8,
    0xDDDB,
    0xDDFF,
    0xDE14,
    0xDE22,
    0xDE24,
    0xDE38,
    0xDE43,
    0xDE4A,
    0xDE50,
    0xDE54,
    0xDE74,
    0xDE7A,
    0xDE7D,
    0xDE95,
    0xDEA7,
    0xDEAE,
    0xDEB4,
    0xDEB5,
    0xDECD,
    0xDED4,
    0xDEDA,
    0xDEDB,
    0xDEF4,
    0xDEFA,
    0xDEFD,
    0xDF16,
    0xDF1A,
    0xDF48,
    0xDF4E,
    0xDF6E,
    0xDF71,
    0xDF75,
    0xDF7E,
    0xDF91,
    0xDF9A,
    0xDFA2,
    0xDFA8,
    0xDFBB,
    0xDFC0,
    0xDFCF,
    0xDFE9,
    0xDFF4,
    0xE003,
    0xE020,
    0xE026,
    0xE035,
    0xE038,
    0xE055,
    0xE060,
    0xE06F,
    0xE070,
    0xE08D,
    0xE092,
    0xE0A1,
    0xE0A2,
    0xE0BF,
    0xE0C8,
    0xE0CE,
    0xE0DD,
    0xE0E0,
    0xE0FD,
    0xE102,
    0xE111,
    0xE114,
    0xE125,
    0xE134,
    0xE138,
    0xE16D,
    0xE17C,
    0xE186,
    0xE190,
    0xE19E,
    0xE1C9,
    0xE1D4,
    0xE1DB,
    0xE1E6,
    0xE1F0,
    0xE1F7,
    0xE209,
    0xE212,
    0xE243,
    0xE248,
    0xE250,
    0xE25E,
    0xE264,
    0xE267,
    0xE279,
    0xE27C,
    0xE283,
    0xE294,
    0xE29A,
    0xE29D,
    0xE2B2,
    0xE2B8,
    0xE2BB,
    0xE2D0,
    0xE2D6,
    0xE2D9,
    0xE2EB,
    0xE2F0,
    0xE2FF,
    0xE302,
    0xE30D,
    0xE310,
    0xE318,
    0xE322,
    0xE32C,
    0xE337,
    0xE340,
    0xE348,
    0xE37F,
    0xE386,
    0xE38A,
    0xE39C,
    0xE3A0,
    0xE3B0,
    0xE3B3,
    0xE3CC,
    0xE3EC,
    0xE3EE,
    0xE409,
    0xE414,
    0xE420,
    0xE424,
    0xE43E,
    0xE441,
    0xE45E,
    0xE464,
    0xE468,
    0xE48A,
    0xE492,
    0xE4B4,
    0xE4C3,
    0xE4D1,
    0xE4DA,
    0xE4F3,
    0xE4FE,
    0xE50D,
    0xE510,
    0xE52D,
    0xE532,
    0xE541,
    0xE542,
    0xE55F,
    0xE566,
    0xE573,
    0xE58D,
    0xE592,
    0xE5A1,
    0xE5BB,
    0xE5D6,
    0xE5E3,
    0xE5E8,
    0xE5ED,
    0xE5FC,
    0xE606,
    0xE610,
    0xE61E,
    0xE64C,
    0xE656,
    0xE662,
    0xE66C,
    0xE676,
    0xE6A7,
    0xE6AC,
    0xE6B4,
    0xE6C2,
    0xE6C8,
    0xE6CB,
    0xE6DD,
    0xE6E0,
    0xE6E7,
    0xE6F8,
    0xE6FE,
    0xE701,
    0xE716,
    0xE71C,
    0xE71F,
    0xE734,
    0xE73A,
    0xE73D,
    0xE74F,
    0xE754,
    0xE763,
    0xE766,
    0xE771,
    0xE774,
    0xE77C,
    0xE786,
    0xE790,
    0xE79B,
    0xE7A4,
    0xE7AC,
    0xE7E3,
    0xE7EA,
    0xE7EC,
    0xE7FE,
    0xE802,
    0xE812,
    0xE815,
    0xE82E,
    0xE84E,
    0xE850,
    0xE86B,
    0xE876,
    0xE882,
    0xE886,
    0xE8A0,
    0xE8A3,
    0xE8C0,
    0xE8C6,
    0xE8CA,
    0xE8EC,
    0xE8F4,
    0xE916,
    0xE925,
    0xE933,
    0xE93C,
    0xE955,
    0xE960,
    0xE96F,
    0xE972,
    0xE98F,
    0xE994,
    0xE9A3,
    0xE9A4,
    0xE9C1,
    0xE9C8,
    0xE9D5,
    0xE9EF,
    0xE9F4,
    0xEA03,
    0xEA1D,
    0xEA38,
    0xEA45,
    0xEA4A,
    0xEA4F,
    0xEA5E,
    0xEA67,
    0xEA7C,
    0xEAAB,
    0xEABA,
    0xEAC7,
    0xEAD4,
    0xEAD7,
    0xEAE5,
    0xEAF2,
    0xEB0B,
    0xEB12,
    0xEB1C,
    0xEB9D,
    0xEBA0,
    0xEBD0,
    0xEBDD,
    0xEBEC,
    0xEBF0,
    0xEC1C,
    0xEC32,
    0xEC37,
    0xEC3B,
    0xEC62,
    0xEC8E,
    0xECAA,
    0xECAF,
    0xECB3,
    0xECDA,
    0xED06,
    0xED22,
    0xED27,
    0xED2B,
    0xED52,
    0xED7E,
    0xED9A,
    0xED9F,
    0xEDA3,
    0xEDCA,
    0xEDF6,
    0xEE12,
    0xEE17,
    0xEE1B,
    0xEE42,
    0xEE6E,
    0xEE8A,
    0xEE8F,
    0xEE93,
    0xEEA2,
    0xEECA,
    0xEEF6,
    0xEF12,
    0xEF17,
    0xEF1B,
    0xEF42,
    0xEF6E,
    0xEF8A,
    0xEF8F,
    0xEF93,
    0xEFA6,
    0xEFB6,
    0xEFBA,
    0xEFC4,
    0xEFD9,
    0xF008,
    0xF017,
    0xF024,
    0xF032,
    0xF035,
    0xF043,
    0xF050,
    0xF069,
    0xF070,
    0xF07A,
    0xF0FB,
    0xF0FE,
    0xF12E,
    0xF13B,
    0xF14A,
    0xF14E,
    0xF17A,
    0xF190,
    0xF195,
    0xF199,
    0xF1C0,
    0xF1EC,
    0xF208,
    0xF20D,
    0xF211,
    0xF238,
    0xF264,
    0xF280,
    0xF285,
    0xF289,
    0xF2B0,
    0xF2DC,
    0xF2F8,
    0xF2FD,
    0xF301,
    0xF328,
    0xF354,
    0xF370,
    0xF375,
    0xF379,
    0xF3A0,
    0xF3CC,
    0xF3E8,
    0xF3ED,
    0xF3F1,
    0xF400,
    0xF428,
    0xF454,
    0xF470,
    0xF475,
    0xF479,
    0xF4A0,
    0xF4CC,
    0xF4E8,
    0xF4ED,
    0xF4F1,
    0xF504,
    0xF514,
    0xF518,
    0xF522,
    0xF530,
    0xF558,
    0xF55C,
    0xF56C,
    0xF571,
    0xF57A,
    0xF589,
    0xF596,
    0xF5A2,
    0xF5A5,
    0xF5B3,
    0xF5C0,
    0xF5D5,
    0xF5E6,
    0xF5E8,
    0xF616,
    0xF620,
    0xF661,
    0xF670,
    0xF67B,
    0xF67E,
    0xF688,
    0xF697,
    0xF69A,
    0xF6B2,
    0xF6C1,
    0xF6C6,
    0xF6D5,
    0xF6D8,
    0xF6F0,
    0xF6FF,
    0xF706,
    0xF715,
    0xF736,
    0xF73C,
    0xF74B,
    0xF76C,
    0xF783,
    0xF788,
    0xF797,
    0xF7AC,
    0xF7D7,
    0xF7E6,
    0xF7F3,
    0xF800,
    0xF803,
    0xF811,
    0xF81A,
    0xF82F,
    0xF840,
    0xF842,
    0xF870,
    0xF87A,
    0xF8BB,
    0xF8CA,
    0xF8D5,
    0xF8D8,
    0xF8E2,
    0xF8F1,
    0xF8F4,
    0xF90C,
    0xF91B,
    0xF920,
    0xF92F,
    0xF932,
    0xF94A,
    0xF959,
    0xF960,
    0xF96F,
    0xF990,
    0xF996,
    0xF9A5,
    0xF9C6,
    0xF9DD,
    0xF9E2,
    0xFA05,
    0xFA18,
    0xFA26,
    0xFA30,
    0xFA39,
    0xFA56,
};

/// 0EF8:A026-CD1F, from the label `start` until its `retf` (or, for a near
/// helper entered by `call`, its `ret`).
pub fn runA026(m: *Machine, start: u16) void {
    @setEvalBranchQuota(1_000_000);
    sw: switch (start) {
        0xA026 => {
            m.push(m.bp);
            m.bp = m.sp;
            m.sp -%= 0x12; // A026 enter 0x12, 0
            m.push(m.di); // A02A push di
            m.push(m.si); // A02B push si
            m.bx = m.rw(m.bp +% 0x000A); // A02C mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, 0x1); // A02F mov byte ptr [bx], 1
            m.setAl(m.rb(0xA050)); // A032 mov al, byte ptr [0xa050]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // A035 sub ah, ah
            m.ww(m.bp +% 0xFFF4, m.ax); // A037 mov word ptr [bp - 0xc], ax
            m.cmp(u16, m.ax, 0x62); // A03A cmp ax, 0x62
            if (m.zf or m.sf != m.of) continue :sw 0xA066; // A03D jle 0xa066
            m.cmp(u8, m.rb(0xA38F), m.ah()); // A03F cmp byte ptr [0xa38f], ah
            if (m.zf) continue :sw 0xA054; // A043 je 0xa054
            m.setAl(m.rb(0xA38F)); // A045 mov al, byte ptr [0xa38f]
            m.cbw(); // A048 cbw
            m.bx = m.ax; // A049 mov bx, ax
            m.setAl(m.rb(m.bx +% 0xA04A)); // A04B mov al, byte ptr [bx - 0x5fb6]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // A04F sub ah, ah
            m.ww(m.bp +% 0xFFF4, m.ax); // A051 mov word ptr [bp - 0xc], ax
            continue :sw 0xA054; // falls through
        },
        0xA054 => {
            m.mark(0xA054);
            m.cmp(u8, m.rb(0x931A), 0x0); // A054 cmp byte ptr [0x931a], 0
            if (!m.zf) continue :sw 0xA066; // A059 jne 0xa066
            m.cmp(u16, m.ax, 0x62); // A05B cmp ax, 0x62
            if (m.zf or m.sf != m.of) continue :sw 0xA066; // A05E jle 0xa066
            m.ax = m.xor(u16, m.ax, m.ax); // A060 xor ax, ax
            m.si = m.pop(); // A062 pop si
            m.di = m.pop(); // A063 pop di
            m.sp = m.bp;
            m.bp = m.pop(); // A064 leave
            return; // A065 retf
        },
        0xA066 => {
            m.mark(0xA066);
            m.ax = m.xor(u16, m.ax, m.ax); // A066 xor ax, ax
            m.ww(m.bp +% 0xFFFE, m.ax); // A068 mov word ptr [bp - 2], ax
            m.ww(m.bp +% 0xFFFC, m.ax); // A06B mov word ptr [bp - 4], ax
            m.ww(m.bp +% 0xFFFA, m.ax); // A06E mov word ptr [bp - 6], ax
            m.ww(m.bp +% 0xFFF8, m.ax); // A071 mov word ptr [bp - 8], ax
            m.cmp(u8, m.rb(0xA3F4), 0x1); // A074 cmp byte ptr [0xa3f4], 1
            if (!m.zf and m.sf == m.of) continue :sw 0xA080; // A079 jg 0xa080
            m.ww(m.bp +% 0x0006, 0x64); // A07B mov word ptr [bp + 6], 0x64
            continue :sw 0xA080; // falls through
        },
        0xA080 => {
            m.mark(0xA080);
            m.setAl(m.rb(0xA041)); // A080 mov al, byte ptr [0xa041]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // A083 sub ah, ah
            m.di = m.ax; // A085 mov di, ax
            m.cmp(u16, m.di, 0x26); // A087 cmp di, 0x26
            if (!m.zf and m.sf == m.of) continue :sw 0xA08F; // A08A jg 0xa08f
            continue :sw 0xA29A; // A08C jmp 0xa29a
        },
        0xA08F => {
            m.mark(0xA08F);
            m.cmp(u16, m.di, 0x30); // A08F cmp di, 0x30
            if (m.zf or m.sf != m.of) continue :sw 0xA097; // A092 jle 0xa097
            continue :sw 0xAD90; // A094 jmp 0xad90
        },
        0xA097 => {
            m.mark(0xA097);
            m.cmp(u16, m.di, 0x2A); // A097 cmp di, 0x2a
            if (m.zf or m.sf != m.of) continue :sw 0xA0A4; // A09A jle 0xa0a4
            m.cmp(u16, m.di, 0x2F); // A09C cmp di, 0x2f
            if (m.sf == m.of) continue :sw 0xA0A4; // A09F jge 0xa0a4
            continue :sw 0xAD90; // A0A1 jmp 0xad90
        },
        0xA0A4 => {
            m.mark(0xA0A4);
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), 0x63); // A0A4 cmp word ptr [bp - 0xc], 0x63
            if (m.sf != m.of) continue :sw 0xA0AD; // A0A8 jl 0xa0ad
            continue :sw 0xA28D; // A0AA jmp 0xa28d
        },
        0xA0AD => {
            m.mark(0xA0AD);
            m.cmp(u16, m.di, 0x2A); // A0AD cmp di, 0x2a
            if (!m.zf and m.sf == m.of) continue :sw 0xA0B8; // A0B0 jg 0xa0b8
            m.si = 0x20; // A0B2 mov si, 0x20
            continue :sw 0xA0BB; // A0B5 jmp 0xa0bb
        },
        0xA0B8 => {
            m.mark(0xA0B8);
            m.si = 0x25; // A0B8 mov si, 0x25
            continue :sw 0xA0BB; // falls through
        },
        0xA0BB => {
            m.mark(0xA0BB);
            m.ww(m.bp +% 0xFFF6, m.si); // A0BB mov word ptr [bp - 0xa], si
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // A0BE cmp byte ptr [si - 0x610a], 7
            if (m.sf != m.of) continue :sw 0xA0C8; // A0C3 jl 0xa0c8
            continue :sw 0xA1DE; // A0C5 jmp 0xa1de
        },
        0xA0C8 => {
            m.mark(0xA0C8);
            m.bx = m.si; // A0C8 mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // A0CA sub bx, word ptr [bp - 0xc]
            m.setAl(m.rb(m.bx +% 0x0C64)); // A0CD mov al, byte ptr [bx + 0xc64]
            m.cbw(); // A0D1 cbw
            m.di = m.ax; // A0D2 mov di, ax
            m.di = m.@"or"(u16, m.di, m.di); // A0D4 or di, di
            if (!m.zf) continue :sw 0xA0DB; // A0D6 jne 0xa0db
            continue :sw 0xA19A; // A0D8 jmp 0xa19a
        },
        0xA0DB => {
            m.mark(0xA0DB);
            m.si = m.add(u16, m.si, m.di); // A0DB add si, di
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A0DD cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA0DB; // A0E2 je 0xa0db
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // A0E4 cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xA0EC; // A0E7 je 0xa0ec
            continue :sw 0xA1DE; // A0E9 jmp 0xa1de
        },
        0xA0EC => {
            m.mark(0xA0EC);
            m.wb(m.si +% 0x9EF6, 0x0); // A0EC mov byte ptr [si - 0x610a], 0
            m.bx = m.rw(m.bp +% 0xFFF6); // A0F1 mov bx, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.bx +% 0x9EF6), 0x0); // A0F4 cmp byte ptr [bx - 0x610a], 0
            if (m.zf) continue :sw 0xA10C; // A0F9 je 0xa10c
            continue :sw 0xA0FB; // falls through
        },
        0xA0FB => {
            m.mark(0xA0FB);
            m.push(0x1B); // A0FB push 0x1b
            m.push(m.bx); // A0FD push bx
            m.far(.see_black, 0xA0FE); // A0FE lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A103 or ax, ax
            if (!m.zf and m.sf == m.of) continue :sw 0xA10A; // A105 jg 0xa10a
            continue :sw 0xA1D9; // A107 jmp 0xa1d9
        },
        0xA10A => {
            m.mark(0xA10A);
            continue :sw 0xA11D; // A10A jmp 0xa11d
        },
        0xA10C => {
            m.mark(0xA10C);
            m.push(0x1B); // A10C push 0x1b
            m.push(m.rw(m.bp +% 0xFFF6)); // A10E push word ptr [bp - 0xa]
            m.far(.see_black, 0xA111); // A111 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A116 or ax, ax
            if (m.sf != m.of) continue :sw 0xA154; // A118 jl 0xa154
            continue :sw 0xA11A; // falls through
        },
        0xA11A => {
            m.mark(0xA11A);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // A11A inc word ptr [bp - 8]
            continue :sw 0xA11D; // falls through
        },
        0xA11D => {
            m.mark(0xA11D);
            m.wb(m.si +% 0x9EF6, 0xC); // A11D mov byte ptr [si - 0x610a], 0xc
            m.setBl(m.rb(0xA041)); // A122 mov bl, byte ptr [0xa041]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // A126 sub bh, bh
            m.cmp(u8, m.rb(m.bx +% 0x9F0A), 0x8); // A128 cmp byte ptr [bx - 0x60f6], 8
            if (m.zf) continue :sw 0xA13C; // A12D je 0xa13c
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // A12F sub bx, word ptr [bp - 0xc]
            m.cmp(u8, m.rb(m.bx +% 0x0A68), 0x0); // A132 cmp byte ptr [bx + 0xa68], 0
            if (!m.zf) continue :sw 0xA13C; // A137 jne 0xa13c
            continue :sw 0xAD9E; // A139 jmp 0xad9e
        },
        0xA13C => {
            m.mark(0xA13C);
            m.ax = m.rw(0x9356); // A13C mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // A13F cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xA147; // A142 jg 0xa147
            continue :sw 0xADBD; // A144 jmp 0xadbd
        },
        0xA147 => {
            m.mark(0xA147);
            m.cmp(u8, m.rb(0xA40E), 0x0); // A147 cmp byte ptr [0xa40e], 0
            if (!m.zf) continue :sw 0xA151; // A14C jne 0xa151
            continue :sw 0xAD84; // A14E jmp 0xad84
        },
        0xA151 => {
            m.mark(0xA151);
            continue :sw 0xADBD; // A151 jmp 0xadbd
        },
        0xA154 => {
            m.mark(0xA154);
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), 0x26); // A154 cmp word ptr [bp - 0xc], 0x26
            if (!m.zf and m.sf == m.of) continue :sw 0xA166; // A158 jg 0xa166
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), 0x1F); // A15A cmp word ptr [bp - 0xc], 0x1f
            if (m.sf != m.of) continue :sw 0xA166; // A15E jl 0xa166
            m.ww(m.bp +% 0xFFF6, m.sub(u16, m.rw(m.bp +% 0xFFF6), m.di)); // A160 sub word ptr [bp - 0xa], di
            continue :sw 0xA16A; // A163 jmp 0xa16a
        },
        0xA166 => {
            m.mark(0xA166);
            m.ww(m.bp +% 0xFFF6, m.add(u16, m.rw(m.bp +% 0xFFF6), 0xA)); // A166 add word ptr [bp - 0xa], 0xa
            continue :sw 0xA16A; // falls through
        },
        0xA16A => {
            m.mark(0xA16A);
            m.bx = m.rw(m.bp +% 0xFFF6); // A16A mov bx, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.bx +% 0x9EF6), 0x0); // A16D cmp byte ptr [bx - 0x610a], 0
            if (!m.zf) continue :sw 0xA182; // A172 jne 0xa182
            m.push(0x1B); // A174 push 0x1b
            m.push(m.bx); // A176 push bx
            m.far(.see_black, 0xA177); // A177 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A17C or ax, ax
            if (m.sf != m.of) continue :sw 0xA1D9; // A17E jl 0xa1d9
            continue :sw 0xA11A; // A180 jmp 0xa11a
        },
        0xA182 => {
            m.mark(0xA182);
            m.bx = m.rw(m.bp +% 0xFFF6); // A182 mov bx, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.bx +% 0x9EF6), 0x7); // A185 cmp byte ptr [bx - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xA1D9; // A18A jge 0xa1d9
            m.push(0x1B); // A18C push 0x1b
            m.push(m.bx); // A18E push bx
            m.far(.see_black, 0xA18F); // A18F lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A194 or ax, ax
            if (!m.zf and m.sf == m.of) continue :sw 0xA11D; // A196 jg 0xa11d
            continue :sw 0xA1D9; // A198 jmp 0xa1d9
        },
        0xA19A => {
            m.mark(0xA19A);
            m.bx = m.si; // A19A mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // A19C sub bx, word ptr [bp - 0xc]
            m.setAl(m.rb(m.bx +% 0x0B66)); // A19F mov al, byte ptr [bx + 0xb66]
            m.cbw(); // A1A3 cbw
            m.di = m.ax; // A1A4 mov di, ax
            m.di = m.@"or"(u16, m.di, m.di); // A1A6 or di, di
            if (m.zf) continue :sw 0xA1DE; // A1A8 je 0xa1de
            continue :sw 0xA1AA; // falls through
        },
        0xA1AA => {
            m.mark(0xA1AA);
            m.si = m.add(u16, m.si, m.di); // A1AA add si, di
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A1AC cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA1AA; // A1B1 je 0xa1aa
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // A1B3 cmp word ptr [bp - 0xc], si
            if (!m.zf) continue :sw 0xA1DE; // A1B6 jne 0xa1de
            m.wb(m.si +% 0x9EF6, 0x0); // A1B8 mov byte ptr [si - 0x610a], 0
            m.bx = m.rw(m.bp +% 0xFFF6); // A1BD mov bx, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.bx +% 0x9EF6), 0x0); // A1C0 cmp byte ptr [bx - 0x610a], 0
            if (m.zf) continue :sw 0xA1CA; // A1C5 je 0xa1ca
            continue :sw 0xA0FB; // A1C7 jmp 0xa0fb
        },
        0xA1CA => {
            m.mark(0xA1CA);
            m.push(0x1B); // A1CA push 0x1b
            m.push(m.bx); // A1CC push bx
            m.far(.see_black, 0xA1CD); // A1CD lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A1D2 or ax, ax
            if (m.sf != m.of) continue :sw 0xA1D9; // A1D4 jl 0xa1d9
            continue :sw 0xA11A; // A1D6 jmp 0xa11a
        },
        0xA1D9 => {
            m.mark(0xA1D9);
            m.wb(m.si +% 0x9EF6, 0xC); // A1D9 mov byte ptr [si - 0x610a], 0xc
            continue :sw 0xA1DE; // falls through
        },
        0xA1DE => {
            m.mark(0xA1DE);
            m.setAl(m.rb(0xA041)); // A1DE mov al, byte ptr [0xa041]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // A1E1 sub ah, ah
            m.di = m.ax; // A1E3 mov di, ax
            m.cmp(u8, m.rb(m.di +% 0x0850), m.ah()); // A1E5 cmp byte ptr [di + 0x850], ah
            if (m.zf) continue :sw 0xA1EE; // A1E9 je 0xa1ee
            continue :sw 0xA28D; // A1EB jmp 0xa28d
        },
        0xA1EE => {
            m.mark(0xA1EE);
            m.cmp(u16, m.di, 0x2A); // A1EE cmp di, 0x2a
            if (m.sf == m.of) continue :sw 0xA1F8; // A1F1 jge 0xa1f8
            m.si = 0x2A; // A1F3 mov si, 0x2a
            continue :sw 0xA1FB; // A1F6 jmp 0xa1fb
        },
        0xA1F8 => {
            m.mark(0xA1F8);
            m.si = 0x2F; // A1F8 mov si, 0x2f
            continue :sw 0xA1FB; // falls through
        },
        0xA1FB => {
            m.mark(0xA1FB);
            m.ww(m.bp +% 0xFFF6, m.si); // A1FB mov word ptr [bp - 0xa], si
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // A1FE cmp byte ptr [si - 0x610a], 7
            if (m.sf != m.of) continue :sw 0xA208; // A203 jl 0xa208
            continue :sw 0xA28D; // A205 jmp 0xa28d
        },
        0xA208 => {
            m.mark(0xA208);
            m.bx = m.si; // A208 mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // A20A sub bx, word ptr [bp - 0xc]
            m.setAl(m.rb(m.bx +% 0x0B66)); // A20D mov al, byte ptr [bx + 0xb66]
            m.cbw(); // A211 cbw
            m.di = m.ax; // A212 mov di, ax
            m.di = m.@"or"(u16, m.di, m.di); // A214 or di, di
            if (m.zf) continue :sw 0xA28D; // A216 je 0xa28d
            continue :sw 0xA218; // falls through
        },
        0xA218 => {
            m.mark(0xA218);
            m.si = m.add(u16, m.si, m.di); // A218 add si, di
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A21A cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA218; // A21F je 0xa218
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // A221 cmp word ptr [bp - 0xc], si
            if (!m.zf) continue :sw 0xA28D; // A224 jne 0xa28d
            m.wb(m.si +% 0x9EF6, 0x0); // A226 mov byte ptr [si - 0x610a], 0
            m.bx = m.rw(m.bp +% 0xFFF6); // A22B mov bx, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.bx +% 0x9EF6), 0x0); // A22E cmp byte ptr [bx - 0x610a], 0
            if (m.zf) continue :sw 0xA246; // A233 je 0xa246
            m.push(0x1B); // A235 push 0x1b
            m.push(m.bx); // A237 push bx
            m.far(.see_black, 0xA238); // A238 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A23D or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xA288; // A23F jle 0xa288
            continue :sw 0xA11D; // A241 jmp 0xa11d
        },
        0xA246 => {
            m.mark(0xA246);
            m.push(0x1B); // A246 push 0x1b
            m.push(m.bx); // A248 push bx
            m.far(.see_black, 0xA249); // A249 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A24E or ax, ax
            if (m.sf != m.of) continue :sw 0xA255; // A250 jl 0xa255
            continue :sw 0xA11A; // A252 jmp 0xa11a
        },
        0xA255 => {
            m.mark(0xA255);
            m.ww(m.bp +% 0xFFF6, m.sub(u16, m.rw(m.bp +% 0xFFF6), m.di)); // A255 sub word ptr [bp - 0xa], di
            m.bx = m.rw(m.bp +% 0xFFF6); // A258 mov bx, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.bx +% 0x9EF6), 0x0); // A25B cmp byte ptr [bx - 0x610a], 0
            if (!m.zf) continue :sw 0xA272; // A260 jne 0xa272
            m.push(0x1B); // A262 push 0x1b
            m.push(m.bx); // A264 push bx
            m.far(.see_black, 0xA265); // A265 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A26A or ax, ax
            if (m.sf != m.of) continue :sw 0xA288; // A26C jl 0xa288
            continue :sw 0xA11A; // A26E jmp 0xa11a
        },
        0xA272 => {
            m.mark(0xA272);
            m.cmp(u8, m.rb(m.bx +% 0x9EF6), 0x7); // A272 cmp byte ptr [bx - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xA288; // A277 jge 0xa288
            m.push(0x1B); // A279 push 0x1b
            m.push(m.bx); // A27B push bx
            m.far(.see_black, 0xA27C); // A27C lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A281 or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xA288; // A283 jle 0xa288
            continue :sw 0xA11D; // A285 jmp 0xa11d
        },
        0xA288 => {
            m.mark(0xA288);
            m.wb(m.si +% 0x9EF6, 0xC); // A288 mov byte ptr [si - 0x610a], 0xc
            continue :sw 0xA28D; // falls through
        },
        0xA28D => {
            m.mark(0xA28D);
            m.setAl(m.rb(0xA041)); // A28D mov al, byte ptr [0xa041]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // A290 sub ah, ah
            m.di = m.ax; // A292 mov di, ax
            m.di = m.sub(u16, m.di, 0x15); // A294 sub di, 0x15
            continue :sw 0xACDE; // A297 jmp 0xacde
        },
        0xA29A => {
            m.mark(0xA29A);
            m.ax = m.rw(0xA272); // A29A mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // A29D cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xA2A5; // A2A0 jle 0xa2a5
            continue :sw 0xA39A; // A2A2 jmp 0xa39a
        },
        0xA2A5 => {
            m.mark(0xA2A5);
            m.setAl(m.rb(0xA04C)); // A2A5 mov al, byte ptr [0xa04c]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // A2A8 sub ah, ah
            m.di = m.ax; // A2AA mov di, ax
            m.cmp(u8, m.rb(m.di +% 0xA09E), 0x4); // A2AC cmp byte ptr [di - 0x5f62], 4
            if (m.zf or m.sf != m.of) continue :sw 0xA2E8; // A2B1 jle 0xa2e8
            m.setAl(m.rb(m.di +% 0xA09E)); // A2B3 mov al, byte ptr [di - 0x5f62]
            m.cbw(); // A2B7 cbw
            m.bx = m.ax; // A2B8 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // A2BA mov al, byte ptr [bx + 0x490]
            m.cbw(); // A2BE cbw
            m.si = m.ax; // A2BF mov si, ax
            continue :sw 0xA2C1; // falls through
        },
        0xA2C1 => {
            m.mark(0xA2C1);
            m.di = m.add(u16, m.di, m.si); // A2C1 add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // A2C3 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xA2C1; // A2C8 je 0xa2c1
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0xB); // A2CA cmp byte ptr [di - 0x610a], 0xb
            if (m.sf != m.of) continue :sw 0xA2E8; // A2CF jl 0xa2e8
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0xC); // A2D1 cmp byte ptr [di - 0x610a], 0xc
            if (!m.zf and m.sf == m.of) continue :sw 0xA2E8; // A2D6 jg 0xa2e8
            continue :sw 0xA2D8; // falls through
        },
        0xA2D8 => {
            m.mark(0xA2D8);
            m.bx = m.rw(m.bp +% 0x000A); // A2D8 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // A2DB inc byte ptr [bx]
            m.ax = m.rw(m.bp +% 0xFFFE); // A2DD mov ax, word ptr [bp - 2]
            m.ax = m.sub(u16, m.ax, 0x7D0); // A2E0 sub ax, 0x7d0
            m.si = m.pop(); // A2E3 pop si
            m.di = m.pop(); // A2E4 pop di
            m.sp = m.bp;
            m.bp = m.pop(); // A2E5 leave
            return; // A2E6 retf
        },
        0xA2E8 => {
            m.mark(0xA2E8);
            m.setAl(m.rb(0xA04D)); // A2E8 mov al, byte ptr [0xa04d]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // A2EB sub ah, ah
            m.di = m.ax; // A2ED mov di, ax
            m.cmp(u8, m.rb(m.di +% 0xA09E), 0x4); // A2EF cmp byte ptr [di - 0x5f62], 4
            if (m.zf or m.sf != m.of) continue :sw 0xA31B; // A2F4 jle 0xa31b
            m.setAl(m.rb(m.di +% 0xA09E)); // A2F6 mov al, byte ptr [di - 0x5f62]
            m.cbw(); // A2FA cbw
            m.bx = m.ax; // A2FB mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // A2FD mov al, byte ptr [bx + 0x490]
            m.cbw(); // A301 cbw
            m.si = m.ax; // A302 mov si, ax
            continue :sw 0xA304; // falls through
        },
        0xA304 => {
            m.mark(0xA304);
            m.di = m.add(u16, m.di, m.si); // A304 add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // A306 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xA304; // A30B je 0xa304
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0xB); // A30D cmp byte ptr [di - 0x610a], 0xb
            if (m.sf != m.of) continue :sw 0xA31B; // A312 jl 0xa31b
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0xC); // A314 cmp byte ptr [di - 0x610a], 0xc
            if (m.zf or m.sf != m.of) continue :sw 0xA2D8; // A319 jle 0xa2d8
            continue :sw 0xA31B; // falls through
        },
        0xA31B => {
            m.mark(0xA31B);
            m.setAl(m.rb(0xA04E)); // A31B mov al, byte ptr [0xa04e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // A31E sub ah, ah
            m.di = m.ax; // A320 mov di, ax
            m.cmp(u8, m.rb(m.di +% 0xA09E), m.ah()); // A322 cmp byte ptr [di - 0x5f62], ah
            if (m.zf or m.sf != m.of) continue :sw 0xA354; // A326 jle 0xa354
            m.cmp(u8, m.rb(m.di +% 0xA09E), 0x4); // A328 cmp byte ptr [di - 0x5f62], 4
            if (!m.zf and m.sf == m.of) continue :sw 0xA354; // A32D jg 0xa354
            m.setAl(m.rb(m.di +% 0xA09E)); // A32F mov al, byte ptr [di - 0x5f62]
            m.cbw(); // A333 cbw
            m.bx = m.ax; // A334 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // A336 mov al, byte ptr [bx + 0x490]
            m.cbw(); // A33A cbw
            m.si = m.ax; // A33B mov si, ax
            continue :sw 0xA33D; // falls through
        },
        0xA33D => {
            m.mark(0xA33D);
            m.di = m.add(u16, m.di, m.si); // A33D add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // A33F cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xA33D; // A344 je 0xa33d
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0xA); // A346 cmp byte ptr [di - 0x610a], 0xa
            if (m.zf) continue :sw 0xA2D8; // A34B je 0xa2d8
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0xC); // A34D cmp byte ptr [di - 0x610a], 0xc
            if (m.zf) continue :sw 0xA2D8; // A352 je 0xa2d8
            continue :sw 0xA354; // falls through
        },
        0xA354 => {
            m.mark(0xA354);
            m.setAl(m.rb(0xA04F)); // A354 mov al, byte ptr [0xa04f]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // A357 sub ah, ah
            m.di = m.ax; // A359 mov di, ax
            m.cmp(u8, m.rb(m.di +% 0xA09E), m.ah()); // A35B cmp byte ptr [di - 0x5f62], ah
            if (m.zf or m.sf != m.of) continue :sw 0xA393; // A35F jle 0xa393
            m.cmp(u8, m.rb(m.di +% 0xA09E), 0x4); // A361 cmp byte ptr [di - 0x5f62], 4
            if (!m.zf and m.sf == m.of) continue :sw 0xA393; // A366 jg 0xa393
            m.setAl(m.rb(m.di +% 0xA09E)); // A368 mov al, byte ptr [di - 0x5f62]
            m.cbw(); // A36C cbw
            m.bx = m.ax; // A36D mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // A36F mov al, byte ptr [bx + 0x490]
            m.cbw(); // A373 cbw
            m.si = m.ax; // A374 mov si, ax
            continue :sw 0xA376; // falls through
        },
        0xA376 => {
            m.mark(0xA376);
            m.di = m.add(u16, m.di, m.si); // A376 add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // A378 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xA376; // A37D je 0xa376
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0xA); // A37F cmp byte ptr [di - 0x610a], 0xa
            if (!m.zf) continue :sw 0xA389; // A384 jne 0xa389
            continue :sw 0xA2D8; // A386 jmp 0xa2d8
        },
        0xA389 => {
            m.mark(0xA389);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0xC); // A389 cmp byte ptr [di - 0x610a], 0xc
            if (!m.zf) continue :sw 0xA393; // A38E jne 0xa393
            continue :sw 0xA2D8; // A390 jmp 0xa2d8
        },
        0xA393 => {
            m.mark(0xA393);
            m.setAl(m.rb(0xA041)); // A393 mov al, byte ptr [0xa041]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // A396 sub ah, ah
            m.di = m.ax; // A398 mov di, ax
            continue :sw 0xA39A; // falls through
        },
        0xA39A => {
            m.mark(0xA39A);
            m.si = m.rw(m.bp +% 0xFFF4); // A39A mov si, word ptr [bp - 0xc]
            m.cmp(u16, m.si, 0x62); // A39D cmp si, 0x62
            if (m.zf or m.sf != m.of) continue :sw 0xA3A5; // A3A0 jle 0xa3a5
            continue :sw 0xAB9B; // A3A2 jmp 0xab9b
        },
        0xA3A5 => {
            m.mark(0xA3A5);
            m.cmp(u16, m.di, 0x1C); // A3A5 cmp di, 0x1c
            if (!m.zf and m.sf == m.of) continue :sw 0xA3AD; // A3A8 jg 0xa3ad
            continue :sw 0xA7AE; // A3AA jmp 0xa7ae
        },
        0xA3AD => {
            m.mark(0xA3AD);
            m.cmp(u16, m.di, 0x1F); // A3AD cmp di, 0x1f
            if (m.zf) continue :sw 0xA3B5; // A3B0 je 0xa3b5
            continue :sw 0xA55E; // A3B2 jmp 0xa55e
        },
        0xA3B5 => {
            m.mark(0xA3B5);
            m.bx = 0xB86; // A3B5 mov bx, 0xb86
            m.bx = m.sub(u16, m.bx, m.si); // A3B8 sub bx, si
            m.cmp(u8, m.rb(m.bx), 0x0); // A3BA cmp byte ptr [bx], 0
            if (m.zf) continue :sw 0xA42C; // A3BD je 0xa42c
            m.cmp(u8, m.rb(0x9F16), 0x7); // A3BF cmp byte ptr [0x9f16], 7
            if (m.sf != m.of) continue :sw 0xA3C9; // A3C4 jl 0xa3c9
            continue :sw 0xA563; // A3C6 jmp 0xa563
        },
        0xA3C9 => {
            m.mark(0xA3C9);
            m.setAl(m.rb(m.bx)); // A3C9 mov al, byte ptr [bx]
            m.cbw(); // A3CB cbw
            m.di = m.ax; // A3CC mov di, ax
            m.si = m.di +% 0x0020; // A3CE lea si, [di + 0x20]
            continue :sw 0xA3D6; // A3D1 jmp 0xa3d6
        },
        0xA3D4 => {
            m.mark(0xA3D4);
            m.si = m.add(u16, m.si, m.di); // A3D4 add si, di
            continue :sw 0xA3D6; // falls through
        },
        0xA3D6 => {
            m.mark(0xA3D6);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A3D6 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA3D4; // A3DB je 0xa3d4
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // A3DD cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xA3E5; // A3E0 je 0xa3e5
            continue :sw 0xA563; // A3E2 jmp 0xa563
        },
        0xA3E5 => {
            m.mark(0xA3E5);
            m.wb(m.si +% 0x9EF6, 0x0); // A3E5 mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(0x9F16), 0x0); // A3EA cmp byte ptr [0x9f16], 0
            if (!m.zf) continue :sw 0xA468; // A3EF jne 0xa468
            m.push(0x1B); // A3F1 push 0x1b
            m.push(0x20); // A3F3 push 0x20
            m.far(.see_black, 0xA3F5); // A3F5 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A3FA or ax, ax
            if (m.sf != m.of) continue :sw 0xA401; // A3FC jl 0xa401
            continue :sw 0xA11A; // A3FE jmp 0xa11a
        },
        0xA401 => {
            m.mark(0xA401);
            m.cmp(u16, m.di, 0xB); // A401 cmp di, 0xb
            if (!m.zf) continue :sw 0xA424; // A404 jne 0xa424
            m.cmp(u8, m.rb(0x9F0B), 0x0); // A406 cmp byte ptr [0x9f0b], 0
            if (!m.zf) continue :sw 0xA414; // A40B jne 0xa414
            m.push(0x1B); // A40D push 0x1b
            m.push(0x15); // A40F push 0x15
            continue :sw 0xA54F; // A411 jmp 0xa54f
        },
        0xA414 => {
            m.mark(0xA414);
            m.push(0x1B); // A414 push 0x1b
            m.push(0x15); // A416 push 0x15
            m.far(.see_black, 0xA418); // A418 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A41D or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xA424; // A41F jle 0xa424
            continue :sw 0xA11A; // A421 jmp 0xa11a
        },
        0xA424 => {
            m.mark(0xA424);
            m.wb(m.si +% 0x9EF6, 0xC); // A424 mov byte ptr [si - 0x610a], 0xc
            continue :sw 0xA563; // A429 jmp 0xa563
        },
        0xA42C => {
            m.mark(0xA42C);
            m.cmp(u16, m.si, 0x26); // A42C cmp si, 0x26
            if (m.zf or m.sf != m.of) continue :sw 0xA434; // A42F jle 0xa434
            continue :sw 0xA4D8; // A431 jmp 0xa4d8
        },
        0xA434 => {
            m.mark(0xA434);
            m.cmp(u16, m.si, 0x1F); // A434 cmp si, 0x1f
            if (m.sf == m.of) continue :sw 0xA43C; // A437 jge 0xa43c
            continue :sw 0xA563; // A439 jmp 0xa563
        },
        0xA43C => {
            m.mark(0xA43C);
            m.cmp(u8, m.rb(0x9F16), 0x0); // A43C cmp byte ptr [0x9f16], 0
            if (!m.zf) continue :sw 0xA446; // A441 jne 0xa446
            continue :sw 0xA563; // A443 jmp 0xa563
        },
        0xA446 => {
            m.mark(0xA446);
            m.cmp(u8, m.rb(0x9F16), 0x7); // A446 cmp byte ptr [0x9f16], 7
            if (m.sf != m.of) continue :sw 0xA450; // A44B jl 0xa450
            continue :sw 0xA563; // A44D jmp 0xa563
        },
        0xA450 => {
            m.mark(0xA450);
            m.si = 0x21; // A450 mov si, 0x21
            continue :sw 0xA457; // A453 jmp 0xa457
        },
        0xA456 => {
            m.mark(0xA456);
            m.si = m.inc(u16, m.si); // A456 inc si
            continue :sw 0xA457; // falls through
        },
        0xA457 => {
            m.mark(0xA457);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A457 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA456; // A45C je 0xa456
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // A45E cmp word ptr [bp - 0xc], si
            if (!m.zf) continue :sw 0xA47E; // A461 jne 0xa47e
            m.wb(m.si +% 0x9EF6, 0x0); // A463 mov byte ptr [si - 0x610a], 0
            continue :sw 0xA468; // falls through
        },
        0xA468 => {
            m.mark(0xA468);
            m.push(0x1B); // A468 push 0x1b
            m.push(0x20); // A46A push 0x20
            m.far(.see_black, 0xA46C); // A46C lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A471 or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xA424; // A473 jle 0xa424
            m.cmp(u8, m.rb(0x9F16), 0x1); // A475 cmp byte ptr [0x9f16], 1
            continue :sw 0xAB57; // A47A jmp 0xab57
        },
        0xA47E => {
            m.mark(0xA47E);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xB); // A47E cmp byte ptr [si - 0x610a], 0xb
            if (m.zf) continue :sw 0xA488; // A483 je 0xa488
            continue :sw 0xA563; // A485 jmp 0xa563
        },
        0xA488 => {
            m.mark(0xA488);
            m.wb(m.si +% 0x9EF6, 0x0); // A488 mov byte ptr [si - 0x610a], 0
            m.push(0xF); // A48D push 0xf
            m.push(0x20); // A48F push 0x20
            m.far(.see_black, 0xA491); // A491 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A496 or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xA4D0; // A498 jle 0xa4d0
            continue :sw 0xA49A; // falls through
        },
        0xA49A => {
            m.mark(0xA49A);
            m.wb(m.si +% 0x9EF6, 0xB); // A49A mov byte ptr [si - 0x610a], 0xb
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // A49F inc word ptr [bp - 8]
            m.ax = m.rw(0x9356); // A4A2 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // A4A5 cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xA4AD; // A4A8 jl 0xa4ad
            continue :sw 0xAD8C; // A4AA jmp 0xad8c
        },
        0xA4AD => {
            m.mark(0xA4AD);
            m.ax = m.rw(0xA272); // A4AD mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // A4B0 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xA4B8; // A4B3 jg 0xa4b8
            continue :sw 0xADBD; // A4B5 jmp 0xadbd
        },
        0xA4B8 => {
            m.mark(0xA4B8);
            m.cmp(u16, m.rw(m.bp +% 0x0008), 0x0); // A4B8 cmp word ptr [bp + 8], 0
            if (m.zf) continue :sw 0xA4C1; // A4BC je 0xa4c1
            continue :sw 0xADBD; // A4BE jmp 0xadbd
        },
        0xA4C1 => {
            m.mark(0xA4C1);
            m.cmp(u16, m.rw(0xAE3A), 0xED8); // A4C1 cmp word ptr [0xae3a], 0xed8
            if (m.zf or m.sf != m.of) continue :sw 0xA4CC; // A4C7 jle 0xa4cc
            continue :sw 0xAD8C; // A4C9 jmp 0xad8c
        },
        0xA4CC => {
            m.mark(0xA4CC);
            continue :sw 0xADBD; // A4CC jmp 0xadbd
        },
        0xA4D0 => {
            m.mark(0xA4D0);
            m.wb(m.si +% 0x9EF6, 0xB); // A4D0 mov byte ptr [si - 0x610a], 0xb
            continue :sw 0xA563; // A4D5 jmp 0xa563
        },
        0xA4D8 => {
            m.mark(0xA4D8);
            m.cmp(u8, m.rb(m.si +% 0x100A), 0x1); // A4D8 cmp byte ptr [si + 0x100a], 1
            if (!m.zf) continue :sw 0xA51C; // A4DD jne 0xa51c
            m.cmp(u8, m.rb(0x9F1F), 0x0); // A4DF cmp byte ptr [0x9f1f], 0
            if (m.zf) continue :sw 0xA563; // A4E4 je 0xa563
            m.cmp(u8, m.rb(0x9F1F), 0x7); // A4E6 cmp byte ptr [0x9f1f], 7
            if (m.sf == m.of) continue :sw 0xA563; // A4EB jge 0xa563
            m.si = 0x29; // A4ED mov si, 0x29
            continue :sw 0xA4F0; // falls through
        },
        0xA4F0 => {
            m.mark(0xA4F0);
            m.si = m.add(u16, m.si, 0xA); // A4F0 add si, 0xa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A4F3 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA4F0; // A4F8 je 0xa4f0
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // A4FA cmp word ptr [bp - 0xc], si
            if (!m.zf) continue :sw 0xA563; // A4FD jne 0xa563
            m.wb(m.si +% 0x9EF6, 0x0); // A4FF mov byte ptr [si - 0x610a], 0
            m.push(0x1B); // A504 push 0x1b
            m.push(0x29); // A506 push 0x29
            m.far(.see_black, 0xA508); // A508 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A50D or ax, ax
            if (!m.zf and m.sf == m.of) continue :sw 0xA514; // A50F jg 0xa514
            continue :sw 0xA424; // A511 jmp 0xa424
        },
        0xA514 => {
            m.mark(0xA514);
            m.cmp(u8, m.rb(0x9F1F), 0x1); // A514 cmp byte ptr [0x9f1f], 1
            continue :sw 0xAB57; // A519 jmp 0xab57
        },
        0xA51C => {
            m.mark(0xA51C);
            m.cmp(u8, m.rb(m.si +% 0x100A), 0x2); // A51C cmp byte ptr [si + 0x100a], 2
            if (!m.zf) continue :sw 0xA563; // A521 jne 0xa563
            m.cmp(u8, m.rb(0x9F16), 0x7); // A523 cmp byte ptr [0x9f16], 7
            if (m.sf == m.of) continue :sw 0xA563; // A528 jge 0xa563
            m.si = 0x20; // A52A mov si, 0x20
            continue :sw 0xA52D; // falls through
        },
        0xA52D => {
            m.mark(0xA52D);
            m.si = m.add(u16, m.si, 0xA); // A52D add si, 0xa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A530 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA52D; // A535 je 0xa52d
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // A537 cmp word ptr [bp - 0xc], si
            if (!m.zf) continue :sw 0xA563; // A53A jne 0xa563
            m.wb(m.si +% 0x9EF6, 0x0); // A53C mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(0x9F16), 0x0); // A541 cmp byte ptr [0x9f16], 0
            if (m.zf) continue :sw 0xA54B; // A546 je 0xa54b
            continue :sw 0xA468; // A548 jmp 0xa468
        },
        0xA54B => {
            m.mark(0xA54B);
            m.push(0x1B); // A54B push 0x1b
            m.push(0x20); // A54D push 0x20
            continue :sw 0xA54F; // falls through
        },
        0xA54F => {
            m.mark(0xA54F);
            m.far(.see_black, 0xA54F); // A54F lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A554 or ax, ax
            if (m.sf == m.of) continue :sw 0xA55B; // A556 jge 0xa55b
            continue :sw 0xA424; // A558 jmp 0xa424
        },
        0xA55B => {
            m.mark(0xA55B);
            continue :sw 0xA11A; // A55B jmp 0xa11a
        },
        0xA55E => {
            m.mark(0xA55E);
            m.cmp(u16, m.di, 0x20); // A55E cmp di, 0x20
            if (!m.zf) continue :sw 0xA5C0; // A561 jne 0xa5c0
            continue :sw 0xA563; // falls through
        },
        0xA563 => {
            m.mark(0xA563);
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), 0x1C); // A563 cmp word ptr [bp - 0xc], 0x1c
            if (m.zf or m.sf != m.of) continue :sw 0xA56C; // A567 jle 0xa56c
            continue :sw 0xAB94; // A569 jmp 0xab94
        },
        0xA56C => {
            m.mark(0xA56C);
            m.di = 0x16; // A56C mov di, 0x16
            m.cmp(u8, m.rb(0x9F0C), 0x0); // A56F cmp byte ptr [0x9f0c], 0
            if (!m.zf) continue :sw 0xA5A4; // A574 jne 0xa5a4
            m.si = 0x17; // A576 mov si, 0x17
            continue :sw 0xA57D; // A579 jmp 0xa57d
        },
        0xA57C => {
            m.mark(0xA57C);
            m.si = m.inc(u16, m.si); // A57C inc si
            continue :sw 0xA57D; // falls through
        },
        0xA57D => {
            m.mark(0xA57D);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A57D cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA57C; // A582 je 0xa57c
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // A584 cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xA58C; // A587 je 0xa58c
            continue :sw 0xAB94; // A589 jmp 0xab94
        },
        0xA58C => {
            m.mark(0xA58C);
            m.wb(m.si +% 0x9EF6, 0x0); // A58C mov byte ptr [si - 0x610a], 0
            m.push(0x1B); // A591 push 0x1b
            m.push(m.di); // A593 push di
            m.far(.see_black, 0xA594); // A594 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A599 or ax, ax
            if (m.sf != m.of) continue :sw 0xA5A0; // A59B jl 0xa5a0
            continue :sw 0xA11A; // A59D jmp 0xa11a
        },
        0xA5A0 => {
            m.mark(0xA5A0);
            m.di = m.dec(u16, m.di); // A5A0 dec di
            continue :sw 0xAAF8; // A5A1 jmp 0xaaf8
        },
        0xA5A4 => {
            m.mark(0xA5A4);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // A5A4 cmp byte ptr [di - 0x610a], 7
            if (m.sf != m.of) continue :sw 0xA5AE; // A5A9 jl 0xa5ae
            continue :sw 0xAB94; // A5AB jmp 0xab94
        },
        0xA5AE => {
            m.mark(0xA5AE);
            m.si = 0x17; // A5AE mov si, 0x17
            continue :sw 0xA5B5; // A5B1 jmp 0xa5b5
        },
        0xA5B4 => {
            m.mark(0xA5B4);
            m.si = m.inc(u16, m.si); // A5B4 inc si
            continue :sw 0xA5B5; // falls through
        },
        0xA5B5 => {
            m.mark(0xA5B5);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A5B5 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA5B4; // A5BA je 0xa5b4
            continue :sw 0xA79E; // A5BC jmp 0xa79e
        },
        0xA5C0 => {
            m.mark(0xA5C0);
            m.cmp(u16, m.di, 0x26); // A5C0 cmp di, 0x26
            if (m.zf) continue :sw 0xA5C8; // A5C3 je 0xa5c8
            continue :sw 0xA73E; // A5C5 jmp 0xa73e
        },
        0xA5C8 => {
            m.mark(0xA5C8);
            m.bx = 0xB8B; // A5C8 mov bx, 0xb8b
            m.bx = m.sub(u16, m.bx, m.si); // A5CB sub bx, si
            m.cmp(u8, m.rb(m.bx), 0x0); // A5CD cmp byte ptr [bx], 0
            if (m.zf) continue :sw 0xA63E; // A5D0 je 0xa63e
            m.cmp(u8, m.rb(0x9F1B), 0x7); // A5D2 cmp byte ptr [0x9f1b], 7
            if (m.sf != m.of) continue :sw 0xA5DC; // A5D7 jl 0xa5dc
            continue :sw 0xA746; // A5D9 jmp 0xa746
        },
        0xA5DC => {
            m.mark(0xA5DC);
            m.setAl(m.rb(m.bx)); // A5DC mov al, byte ptr [bx]
            m.cbw(); // A5DE cbw
            m.di = m.ax; // A5DF mov di, ax
            m.si = m.di +% 0x0025; // A5E1 lea si, [di + 0x25]
            continue :sw 0xA5E8; // A5E4 jmp 0xa5e8
        },
        0xA5E6 => {
            m.mark(0xA5E6);
            m.si = m.add(u16, m.si, m.di); // A5E6 add si, di
            continue :sw 0xA5E8; // falls through
        },
        0xA5E8 => {
            m.mark(0xA5E8);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A5E8 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA5E6; // A5ED je 0xa5e6
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // A5EF cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xA5F7; // A5F2 je 0xa5f7
            continue :sw 0xA746; // A5F4 jmp 0xa746
        },
        0xA5F7 => {
            m.mark(0xA5F7);
            m.wb(m.si +% 0x9EF6, 0x0); // A5F7 mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(0x9F1B), 0x0); // A5FC cmp byte ptr [0x9f1b], 0
            if (!m.zf) continue :sw 0xA676; // A601 jne 0xa676
            m.push(0x1B); // A603 push 0x1b
            m.push(0x25); // A605 push 0x25
            m.far(.see_black, 0xA607); // A607 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A60C or ax, ax
            if (m.sf != m.of) continue :sw 0xA613; // A60E jl 0xa613
            continue :sw 0xA11A; // A610 jmp 0xa11a
        },
        0xA613 => {
            m.mark(0xA613);
            m.cmp(u16, m.di, 0x9); // A613 cmp di, 9
            if (!m.zf) continue :sw 0xA636; // A616 jne 0xa636
            m.cmp(u8, m.rb(0x9F12), 0x0); // A618 cmp byte ptr [0x9f12], 0
            if (!m.zf) continue :sw 0xA626; // A61D jne 0xa626
            m.push(0x1B); // A61F push 0x1b
            m.push(0x1C); // A621 push 0x1c
            continue :sw 0xA72F; // A623 jmp 0xa72f
        },
        0xA626 => {
            m.mark(0xA626);
            m.push(0x1B); // A626 push 0x1b
            m.push(0x1C); // A628 push 0x1c
            m.far(.see_black, 0xA62A); // A62A lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A62F or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xA636; // A631 jle 0xa636
            continue :sw 0xA11A; // A633 jmp 0xa11a
        },
        0xA636 => {
            m.mark(0xA636);
            m.wb(m.si +% 0x9EF6, 0xC); // A636 mov byte ptr [si - 0x610a], 0xc
            continue :sw 0xA746; // A63B jmp 0xa746
        },
        0xA63E => {
            m.mark(0xA63E);
            m.cmp(u16, m.si, 0x26); // A63E cmp si, 0x26
            if (!m.zf and m.sf == m.of) continue :sw 0xA6B4; // A641 jg 0xa6b4
            m.cmp(u16, m.si, 0x1F); // A643 cmp si, 0x1f
            if (m.sf == m.of) continue :sw 0xA64B; // A646 jge 0xa64b
            continue :sw 0xA746; // A648 jmp 0xa746
        },
        0xA64B => {
            m.mark(0xA64B);
            m.cmp(u8, m.rb(0x9F1B), 0x0); // A64B cmp byte ptr [0x9f1b], 0
            if (!m.zf) continue :sw 0xA655; // A650 jne 0xa655
            continue :sw 0xA746; // A652 jmp 0xa746
        },
        0xA655 => {
            m.mark(0xA655);
            m.cmp(u8, m.rb(0x9F1B), 0x7); // A655 cmp byte ptr [0x9f1b], 7
            if (m.sf != m.of) continue :sw 0xA65F; // A65A jl 0xa65f
            continue :sw 0xA746; // A65C jmp 0xa746
        },
        0xA65F => {
            m.mark(0xA65F);
            m.si = 0x24; // A65F mov si, 0x24
            continue :sw 0xA665; // A662 jmp 0xa665
        },
        0xA664 => {
            m.mark(0xA664);
            m.si = m.dec(u16, m.si); // A664 dec si
            continue :sw 0xA665; // falls through
        },
        0xA665 => {
            m.mark(0xA665);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A665 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA664; // A66A je 0xa664
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // A66C cmp word ptr [bp - 0xc], si
            if (!m.zf) continue :sw 0xA68C; // A66F jne 0xa68c
            m.wb(m.si +% 0x9EF6, 0x0); // A671 mov byte ptr [si - 0x610a], 0
            continue :sw 0xA676; // falls through
        },
        0xA676 => {
            m.mark(0xA676);
            m.push(0x1B); // A676 push 0x1b
            m.push(0x25); // A678 push 0x25
            m.far(.see_black, 0xA67A); // A67A lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A67F or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xA636; // A681 jle 0xa636
            m.cmp(u8, m.rb(0x9F1B), 0x1); // A683 cmp byte ptr [0x9f1b], 1
            continue :sw 0xAB57; // A688 jmp 0xab57
        },
        0xA68C => {
            m.mark(0xA68C);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xB); // A68C cmp byte ptr [si - 0x610a], 0xb
            if (m.zf) continue :sw 0xA696; // A691 je 0xa696
            continue :sw 0xA746; // A693 jmp 0xa746
        },
        0xA696 => {
            m.mark(0xA696);
            m.wb(m.si +% 0x9EF6, 0x0); // A696 mov byte ptr [si - 0x610a], 0
            m.push(0xF); // A69B push 0xf
            m.push(0x25); // A69D push 0x25
            m.far(.see_black, 0xA69F); // A69F lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A6A4 or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xA6AB; // A6A6 jle 0xa6ab
            continue :sw 0xA49A; // A6A8 jmp 0xa49a
        },
        0xA6AB => {
            m.mark(0xA6AB);
            m.wb(m.si +% 0x9EF6, 0xB); // A6AB mov byte ptr [si - 0x610a], 0xb
            continue :sw 0xA746; // A6B0 jmp 0xa746
        },
        0xA6B4 => {
            m.mark(0xA6B4);
            m.cmp(u8, m.rb(m.si +% 0x100A), 0x8); // A6B4 cmp byte ptr [si + 0x100a], 8
            if (!m.zf) continue :sw 0xA6FC; // A6B9 jne 0xa6fc
            m.cmp(u8, m.rb(0x9F26), 0x0); // A6BB cmp byte ptr [0x9f26], 0
            if (!m.zf) continue :sw 0xA6C5; // A6C0 jne 0xa6c5
            continue :sw 0xA746; // A6C2 jmp 0xa746
        },
        0xA6C5 => {
            m.mark(0xA6C5);
            m.cmp(u8, m.rb(0x9F26), 0x7); // A6C5 cmp byte ptr [0x9f26], 7
            if (m.sf == m.of) continue :sw 0xA746; // A6CA jge 0xa746
            m.si = 0x30; // A6CC mov si, 0x30
            continue :sw 0xA6CF; // falls through
        },
        0xA6CF => {
            m.mark(0xA6CF);
            m.si = m.add(u16, m.si, 0xA); // A6CF add si, 0xa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A6D2 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA6CF; // A6D7 je 0xa6cf
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // A6D9 cmp word ptr [bp - 0xc], si
            if (!m.zf) continue :sw 0xA746; // A6DC jne 0xa746
            m.wb(m.si +% 0x9EF6, 0x0); // A6DE mov byte ptr [si - 0x610a], 0
            m.push(0x1B); // A6E3 push 0x1b
            m.push(0x30); // A6E5 push 0x30
            m.far(.see_black, 0xA6E7); // A6E7 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A6EC or ax, ax
            if (!m.zf and m.sf == m.of) continue :sw 0xA6F3; // A6EE jg 0xa6f3
            continue :sw 0xA636; // A6F0 jmp 0xa636
        },
        0xA6F3 => {
            m.mark(0xA6F3);
            m.cmp(u8, m.rb(0x9F26), 0x1); // A6F3 cmp byte ptr [0x9f26], 1
            continue :sw 0xAB57; // A6F8 jmp 0xab57
        },
        0xA6FC => {
            m.mark(0xA6FC);
            m.cmp(u8, m.rb(m.si +% 0x100A), 0x7); // A6FC cmp byte ptr [si + 0x100a], 7
            if (!m.zf) continue :sw 0xA746; // A701 jne 0xa746
            m.cmp(u8, m.rb(0x9F1B), 0x7); // A703 cmp byte ptr [0x9f1b], 7
            if (m.sf == m.of) continue :sw 0xA746; // A708 jge 0xa746
            m.si = 0x25; // A70A mov si, 0x25
            continue :sw 0xA70D; // falls through
        },
        0xA70D => {
            m.mark(0xA70D);
            m.si = m.add(u16, m.si, 0xA); // A70D add si, 0xa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A710 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA70D; // A715 je 0xa70d
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // A717 cmp word ptr [bp - 0xc], si
            if (!m.zf) continue :sw 0xA746; // A71A jne 0xa746
            m.wb(m.si +% 0x9EF6, 0x0); // A71C mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(0x9F1B), 0x0); // A721 cmp byte ptr [0x9f1b], 0
            if (m.zf) continue :sw 0xA72B; // A726 je 0xa72b
            continue :sw 0xA676; // A728 jmp 0xa676
        },
        0xA72B => {
            m.mark(0xA72B);
            m.push(0x1B); // A72B push 0x1b
            m.push(0x25); // A72D push 0x25
            continue :sw 0xA72F; // falls through
        },
        0xA72F => {
            m.mark(0xA72F);
            m.far(.see_black, 0xA72F); // A72F lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A734 or ax, ax
            if (m.sf == m.of) continue :sw 0xA73B; // A736 jge 0xa73b
            continue :sw 0xA636; // A738 jmp 0xa636
        },
        0xA73B => {
            m.mark(0xA73B);
            continue :sw 0xA11A; // A73B jmp 0xa11a
        },
        0xA73E => {
            m.mark(0xA73E);
            m.cmp(u16, m.di, 0x25); // A73E cmp di, 0x25
            if (m.zf) continue :sw 0xA746; // A741 je 0xa746
            continue :sw 0xAB94; // A743 jmp 0xab94
        },
        0xA746 => {
            m.mark(0xA746);
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), 0x1A); // A746 cmp word ptr [bp - 0xc], 0x1a
            if (m.zf or m.sf != m.of) continue :sw 0xA74F; // A74A jle 0xa74f
            continue :sw 0xAB94; // A74C jmp 0xab94
        },
        0xA74F => {
            m.mark(0xA74F);
            m.di = 0x1B; // A74F mov di, 0x1b
            m.cmp(u8, m.rb(0x9F11), 0x0); // A752 cmp byte ptr [0x9f11], 0
            if (!m.zf) continue :sw 0xA786; // A757 jne 0xa786
            m.si = 0x1A; // A759 mov si, 0x1a
            continue :sw 0xA75F; // A75C jmp 0xa75f
        },
        0xA75E => {
            m.mark(0xA75E);
            m.si = m.dec(u16, m.si); // A75E dec si
            continue :sw 0xA75F; // falls through
        },
        0xA75F => {
            m.mark(0xA75F);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A75F cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA75E; // A764 je 0xa75e
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // A766 cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xA76E; // A769 je 0xa76e
            continue :sw 0xAB94; // A76B jmp 0xab94
        },
        0xA76E => {
            m.mark(0xA76E);
            m.wb(m.si +% 0x9EF6, 0x0); // A76E mov byte ptr [si - 0x610a], 0
            m.push(0x1B); // A773 push 0x1b
            m.push(m.di); // A775 push di
            m.far(.see_black, 0xA776); // A776 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A77B or ax, ax
            if (m.sf != m.of) continue :sw 0xA782; // A77D jl 0xa782
            continue :sw 0xA11A; // A77F jmp 0xa11a
        },
        0xA782 => {
            m.mark(0xA782);
            m.di = m.inc(u16, m.di); // A782 inc di
            continue :sw 0xAAF8; // A783 jmp 0xaaf8
        },
        0xA786 => {
            m.mark(0xA786);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // A786 cmp byte ptr [di - 0x610a], 7
            if (m.sf != m.of) continue :sw 0xA790; // A78B jl 0xa790
            continue :sw 0xAB94; // A78D jmp 0xab94
        },
        0xA790 => {
            m.mark(0xA790);
            m.si = 0x1A; // A790 mov si, 0x1a
            continue :sw 0xA797; // A793 jmp 0xa797
        },
        0xA796 => {
            m.mark(0xA796);
            m.si = m.dec(u16, m.si); // A796 dec si
            continue :sw 0xA797; // falls through
        },
        0xA797 => {
            m.mark(0xA797);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A797 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA796; // A79C je 0xa796
            continue :sw 0xA79E; // falls through
        },
        0xA79E => {
            m.mark(0xA79E);
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // A79E cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xA7A6; // A7A1 je 0xa7a6
            continue :sw 0xAB94; // A7A3 jmp 0xab94
        },
        0xA7A6 => {
            m.mark(0xA7A6);
            m.wb(m.si +% 0x9EF6, 0x0); // A7A6 mov byte ptr [si - 0x610a], 0
            continue :sw 0xAB80; // A7AB jmp 0xab80
        },
        0xA7AE => {
            m.mark(0xA7AE);
            m.cmp(u16, m.di, 0x1A); // A7AE cmp di, 0x1a
            if (m.sf != m.of) continue :sw 0xA7D0; // A7B1 jl 0xa7d0
            m.cmp(u8, m.rb(0x37FF), 0x0); // A7B3 cmp byte ptr [0x37ff], 0
            if (m.zf) continue :sw 0xA7C1; // A7B8 je 0xa7c1
            m.cmp(u8, m.rb(0x9F1B), 0x1); // A7BA cmp byte ptr [0x9f1b], 1
            if (m.zf) continue :sw 0xA7F1; // A7BF je 0xa7f1
            continue :sw 0xA7C1; // falls through
        },
        0xA7C1 => {
            m.mark(0xA7C1);
            m.cmp(u8, m.rb(0x3800), 0x0); // A7C1 cmp byte ptr [0x3800], 0
            if (m.zf) continue :sw 0xA807; // A7C6 je 0xa807
            m.cmp(u8, m.rb(0x9F1C), 0x1); // A7C8 cmp byte ptr [0x9f1c], 1
            continue :sw 0xA7EF; // A7CD jmp 0xa7ef
        },
        0xA7D0 => {
            m.mark(0xA7D0);
            m.cmp(u16, m.di, 0x17); // A7D0 cmp di, 0x17
            if (!m.zf and m.sf == m.of) continue :sw 0xA807; // A7D3 jg 0xa807
            m.cmp(u8, m.rb(0x37FA), 0x0); // A7D5 cmp byte ptr [0x37fa], 0
            if (m.zf) continue :sw 0xA7E3; // A7DA je 0xa7e3
            m.cmp(u8, m.rb(0x9F16), 0x1); // A7DC cmp byte ptr [0x9f16], 1
            if (m.zf) continue :sw 0xA7F1; // A7E1 je 0xa7f1
            continue :sw 0xA7E3; // falls through
        },
        0xA7E3 => {
            m.mark(0xA7E3);
            m.cmp(u8, m.rb(0x37F9), 0x0); // A7E3 cmp byte ptr [0x37f9], 0
            if (m.zf) continue :sw 0xA807; // A7E8 je 0xa807
            m.cmp(u8, m.rb(0x9F15), 0x1); // A7EA cmp byte ptr [0x9f15], 1
            continue :sw 0xA7EF; // falls through
        },
        0xA7EF => {
            m.mark(0xA7EF);
            if (!m.zf) continue :sw 0xA807; // A7EF jne 0xa807
            continue :sw 0xA7F1; // falls through
        },
        0xA7F1 => {
            m.mark(0xA7F1);
            m.ax = m.rw(0xA272); // A7F1 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // A7F4 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xA803; // A7F7 jg 0xa803
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x12C)); // A7F9 sub word ptr [bp - 2], 0x12c
            m.bx = m.rw(m.bp +% 0x000A); // A7FE mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // A801 inc byte ptr [bx]
            continue :sw 0xA803; // falls through
        },
        0xA803 => {
            m.mark(0xA803);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x18)); // A803 sub word ptr [bp - 4], 0x18
            continue :sw 0xA807; // falls through
        },
        0xA807 => {
            m.mark(0xA807);
            m.cmp(u16, m.si, 0x26); // A807 cmp si, 0x26
            if (m.zf or m.sf != m.of) continue :sw 0xA80F; // A80A jle 0xa80f
            continue :sw 0xA918; // A80C jmp 0xa918
        },
        0xA80F => {
            m.mark(0xA80F);
            m.cmp(u16, m.si, 0x1F); // A80F cmp si, 0x1f
            if (m.sf == m.of) continue :sw 0xA817; // A812 jge 0xa817
            continue :sw 0xA918; // A814 jmp 0xa918
        },
        0xA817 => {
            m.mark(0xA817);
            m.di = m.add(u16, m.di, 0x9); // A817 add di, 9
            m.cmp(u16, m.di, m.si); // A81A cmp di, si
            if (m.zf or m.sf != m.of) continue :sw 0xA892; // A81C jle 0xa892
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // A81E cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xA87A; // A823 jne 0xa87a
            m.si = m.di; // A825 mov si, di
            continue :sw 0xA827; // falls through
        },
        0xA827 => {
            m.mark(0xA827);
            m.si = m.dec(u16, m.si); // A827 dec si
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A828 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA827; // A82D je 0xa827
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // A82F cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xA837; // A832 je 0xa837
            continue :sw 0xAB94; // A834 jmp 0xab94
        },
        0xA837 => {
            m.mark(0xA837);
            m.wb(m.si +% 0x9EF6, 0x0); // A837 mov byte ptr [si - 0x610a], 0
            m.push(0x1B); // A83C push 0x1b
            m.push(m.di); // A83E push di
            m.far(.see_black, 0xA83F); // A83F lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A844 or ax, ax
            if (m.sf != m.of) continue :sw 0xA84B; // A846 jl 0xa84b
            continue :sw 0xA11A; // A848 jmp 0xa11a
        },
        0xA84B => {
            m.mark(0xA84B);
            m.di = m.inc(u16, m.di); // A84B inc di
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // A84C cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xA86D; // A851 jne 0xa86d
            m.push(0x1B); // A853 push 0x1b
            m.push(m.di); // A855 push di
            m.far(.see_black, 0xA856); // A856 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A85B or ax, ax
            if (m.sf != m.of) continue :sw 0xA862; // A85D jl 0xa862
            continue :sw 0xA11A; // A85F jmp 0xa11a
        },
        0xA862 => {
            m.mark(0xA862);
            m.di = m.inc(u16, m.di); // A862 inc di
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // A863 cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xA86D; // A868 jne 0xa86d
            continue :sw 0xAAFF; // A86A jmp 0xaaff
        },
        0xA86D => {
            m.mark(0xA86D);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // A86D cmp byte ptr [di - 0x610a], 7
            if (m.sf != m.of) continue :sw 0xA877; // A872 jl 0xa877
            continue :sw 0xAB8F; // A874 jmp 0xab8f
        },
        0xA877 => {
            m.mark(0xA877);
            continue :sw 0xAB46; // A877 jmp 0xab46
        },
        0xA87A => {
            m.mark(0xA87A);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // A87A cmp byte ptr [di - 0x610a], 7
            if (m.sf != m.of) continue :sw 0xA884; // A87F jl 0xa884
            continue :sw 0xAB94; // A881 jmp 0xab94
        },
        0xA884 => {
            m.mark(0xA884);
            m.si = m.di; // A884 mov si, di
            continue :sw 0xA886; // falls through
        },
        0xA886 => {
            m.mark(0xA886);
            m.si = m.dec(u16, m.si); // A886 dec si
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A887 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA886; // A88C je 0xa886
            continue :sw 0xA9F5; // A88E jmp 0xa9f5
        },
        0xA892 => {
            m.mark(0xA892);
            m.di = m.add(u16, m.di, 0x2); // A892 add di, 2
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // A895 cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xA8E4; // A89A jne 0xa8e4
            m.si = m.di; // A89C mov si, di
            continue :sw 0xA89E; // falls through
        },
        0xA89E => {
            m.mark(0xA89E);
            m.si = m.inc(u16, m.si); // A89E inc si
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A89F cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA89E; // A8A4 je 0xa89e
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // A8A6 cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xA8AE; // A8A9 je 0xa8ae
            continue :sw 0xAB94; // A8AB jmp 0xab94
        },
        0xA8AE => {
            m.mark(0xA8AE);
            m.wb(m.si +% 0x9EF6, 0x0); // A8AE mov byte ptr [si - 0x610a], 0
            m.push(0x1B); // A8B3 push 0x1b
            m.push(m.di); // A8B5 push di
            m.far(.see_black, 0xA8B6); // A8B6 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A8BB or ax, ax
            if (m.sf != m.of) continue :sw 0xA8C2; // A8BD jl 0xa8c2
            continue :sw 0xA11A; // A8BF jmp 0xa11a
        },
        0xA8C2 => {
            m.mark(0xA8C2);
            m.di = m.dec(u16, m.di); // A8C2 dec di
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // A8C3 cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xA86D; // A8C8 jne 0xa86d
            m.push(0x1B); // A8CA push 0x1b
            m.push(m.di); // A8CC push di
            m.far(.see_black, 0xA8CD); // A8CD lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A8D2 or ax, ax
            if (m.sf != m.of) continue :sw 0xA8D9; // A8D4 jl 0xa8d9
            continue :sw 0xA11A; // A8D6 jmp 0xa11a
        },
        0xA8D9 => {
            m.mark(0xA8D9);
            m.di = m.dec(u16, m.di); // A8D9 dec di
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // A8DA cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xA86D; // A8DF jne 0xa86d
            continue :sw 0xAAFF; // A8E1 jmp 0xaaff
        },
        0xA8E4 => {
            m.mark(0xA8E4);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // A8E4 cmp byte ptr [di - 0x610a], 7
            if (m.sf != m.of) continue :sw 0xA8EE; // A8E9 jl 0xa8ee
            continue :sw 0xAB94; // A8EB jmp 0xab94
        },
        0xA8EE => {
            m.mark(0xA8EE);
            m.si = m.di; // A8EE mov si, di
            continue :sw 0xA8F0; // falls through
        },
        0xA8F0 => {
            m.mark(0xA8F0);
            m.si = m.inc(u16, m.si); // A8F0 inc si
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A8F1 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA8F0; // A8F6 je 0xa8f0
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // A8F8 cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xA900; // A8FB je 0xa900
            continue :sw 0xAB94; // A8FD jmp 0xab94
        },
        0xA900 => {
            m.mark(0xA900);
            m.wb(m.si +% 0x9EF6, 0x0); // A900 mov byte ptr [si - 0x610a], 0
            m.push(0x1B); // A905 push 0x1b
            m.push(m.di); // A907 push di
            m.far(.see_black, 0xA908); // A908 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A90D or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xA914; // A90F jle 0xa914
            continue :sw 0xAB52; // A911 jmp 0xab52
        },
        0xA914 => {
            m.mark(0xA914);
            continue :sw 0xAB8F; // A914 jmp 0xab8f
        },
        0xA918 => {
            m.mark(0xA918);
            m.ax = 0xB0; // A918 mov ax, 0xb0
            m.ax = m.sub(u16, m.ax, m.si); // A91B sub ax, si
            m.si = m.ax; // A91D mov si, ax
            m.bx = m.ax; // A91F mov bx, ax
            m.di = m.add(u16, m.di, 0xA); // A921 add di, 0xa
            m.bx = m.add(u16, m.bx, m.di); // A924 add bx, di
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), 0x0); // A926 cmp byte ptr [bx + 0xab6], 0
            if (!m.zf) continue :sw 0xA930; // A92B jne 0xa930
            continue :sw 0xAA06; // A92D jmp 0xaa06
        },
        0xA930 => {
            m.mark(0xA930);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // A930 cmp byte ptr [di - 0x610a], 7
            if (m.sf != m.of) continue :sw 0xA93A; // A935 jl 0xa93a
            continue :sw 0xAA06; // A937 jmp 0xaa06
        },
        0xA93A => {
            m.mark(0xA93A);
            m.setAl(m.rb(m.bx +% 0x0AB6)); // A93A mov al, byte ptr [bx + 0xab6]
            m.cbw(); // A93E cbw
            m.si = m.ax; // A93F mov si, ax
            continue :sw 0xA941; // falls through
        },
        0xA941 => {
            m.mark(0xA941);
            m.di = m.add(u16, m.di, m.si); // A941 add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // A943 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xA941; // A948 je 0xa941
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.di); // A94A cmp word ptr [bp - 0xc], di
            if (!m.zf) continue :sw 0xA9B3; // A94D jne 0xa9b3
            m.ww(m.bp +% 0xFFF6, m.si); // A94F mov word ptr [bp - 0xa], si
            m.si = m.di; // A952 mov si, di
            m.setAl(m.rb(0xA041)); // A954 mov al, byte ptr [0xa041]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // A957 sub ah, ah
            m.ax = m.add(u16, m.ax, 0xA); // A959 add ax, 0xa
            m.di = m.ax; // A95C mov di, ax
            m.wb(m.si +% 0x9EF6, 0x0); // A95E mov byte ptr [si - 0x610a], 0
            m.bx = m.di; // A963 mov bx, di
            m.cmp(u8, m.rb(m.bx +% 0x9EF6), 0x0); // A965 cmp byte ptr [bx - 0x610a], 0
            if (m.zf) continue :sw 0xA96F; // A96A je 0xa96f
            continue :sw 0xAA87; // A96C jmp 0xaa87
        },
        0xA96F => {
            m.mark(0xA96F);
            m.push(0x1B); // A96F push 0x1b
            m.push(m.di); // A971 push di
            m.far(.see_black, 0xA972); // A972 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A977 or ax, ax
            if (m.sf != m.of) continue :sw 0xA97E; // A979 jl 0xa97e
            continue :sw 0xA11A; // A97B jmp 0xa11a
        },
        0xA97E => {
            m.mark(0xA97E);
            m.di = m.sub(u16, m.di, m.rw(m.bp +% 0xFFF6)); // A97E sub di, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // A981 cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xA998; // A986 jne 0xa998
            m.push(0x1B); // A988 push 0x1b
            m.push(m.di); // A98A push di
            m.far(.see_black, 0xA98B); // A98B lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A990 or ax, ax
            if (m.sf != m.of) continue :sw 0xA9AE; // A992 jl 0xa9ae
            continue :sw 0xA11A; // A994 jmp 0xa11a
        },
        0xA998 => {
            m.mark(0xA998);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // A998 cmp byte ptr [di - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xA9AE; // A99D jge 0xa9ae
            m.push(0x1B); // A99F push 0x1b
            m.push(m.di); // A9A1 push di
            m.far(.see_black, 0xA9A2); // A9A2 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // A9A7 or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xA9AE; // A9A9 jle 0xa9ae
            continue :sw 0xA11D; // A9AB jmp 0xa11d
        },
        0xA9AE => {
            m.mark(0xA9AE);
            m.wb(m.si +% 0x9EF6, 0xC); // A9AE mov byte ptr [si - 0x610a], 0xc
            continue :sw 0xA9B3; // falls through
        },
        0xA9B3 => {
            m.mark(0xA9B3);
            m.setAl(m.rb(0xA22E)); // A9B3 mov al, byte ptr [0xa22e]
            m.cbw(); // A9B6 cbw
            m.bx = m.rw(m.bp +% 0xFFF4); // A9B7 mov bx, word ptr [bp - 0xc]
            m.bx = m.sub(u16, m.bx, m.ax); // A9BA sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0D4E)); // A9BC mov al, byte ptr [bx + 0xd4e]
            m.cbw(); // A9C0 cbw
            m.si = m.ax; // A9C1 mov si, ax
            m.@"test"(u16, m.si, 0x2); // A9C3 test si, 2
            if (!m.zf) continue :sw 0xA9CC; // A9C7 jne 0xa9cc
            continue :sw 0xAAAC; // A9C9 jmp 0xaaac
        },
        0xA9CC => {
            m.mark(0xA9CC);
            m.setAl(m.rb(0xA041)); // A9CC mov al, byte ptr [0xa041]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // A9CF sub ah, ah
            m.di = m.ax; // A9D1 mov di, ax
            m.di = m.add(u16, m.di, 0xA); // A9D3 add di, 0xa
            m.cmp(u8, m.rb(m.di +% 0x9EF6), m.ah()); // A9D6 cmp byte ptr [di - 0x610a], ah
            if (!m.zf) continue :sw 0xA9DF; // A9DA jne 0xa9df
            continue :sw 0xAB94; // A9DC jmp 0xab94
        },
        0xA9DF => {
            m.mark(0xA9DF);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // A9DF cmp byte ptr [di - 0x610a], 7
            if (m.sf != m.of) continue :sw 0xA9E9; // A9E4 jl 0xa9e9
            continue :sw 0xAB94; // A9E6 jmp 0xab94
        },
        0xA9E9 => {
            m.mark(0xA9E9);
            m.si = m.di; // A9E9 mov si, di
            continue :sw 0xA9EB; // falls through
        },
        0xA9EB => {
            m.mark(0xA9EB);
            m.si = m.add(u16, m.si, 0xA); // A9EB add si, 0xa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // A9EE cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xA9EB; // A9F3 je 0xa9eb
            continue :sw 0xA9F5; // falls through
        },
        0xA9F5 => {
            m.mark(0xA9F5);
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // A9F5 cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xA9FD; // A9F8 je 0xa9fd
            continue :sw 0xAB94; // A9FA jmp 0xab94
        },
        0xA9FD => {
            m.mark(0xA9FD);
            m.wb(m.si +% 0x9EF6, 0x0); // A9FD mov byte ptr [si - 0x610a], 0
            continue :sw 0xAB46; // AA02 jmp 0xab46
        },
        0xAA06 => {
            m.mark(0xAA06);
            m.di = m.inc(u16, m.di); // AA06 inc di
            m.bx = m.di; // AA07 mov bx, di
            m.bx = m.add(u16, m.bx, m.si); // AA09 add bx, si
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), 0x0); // AA0B cmp byte ptr [bx + 0xab6], 0
            if (m.zf) continue :sw 0xAA3A; // AA10 je 0xaa3a
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // AA12 cmp byte ptr [di - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xAA3A; // AA17 jge 0xaa3a
            m.setAl(m.rb(m.bx +% 0x0AB6)); // AA19 mov al, byte ptr [bx + 0xab6]
            m.cbw(); // AA1D cbw
            m.si = m.ax; // AA1E mov si, ax
            continue :sw 0xAA20; // falls through
        },
        0xAA20 => {
            m.mark(0xAA20);
            m.di = m.add(u16, m.di, m.si); // AA20 add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // AA22 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xAA20; // AA27 je 0xaa20
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.di); // AA29 cmp word ptr [bp - 0xc], di
            if (!m.zf) continue :sw 0xA9B3; // AA2C jne 0xa9b3
            m.si = m.di; // AA2E mov si, di
            m.setAl(m.rb(0xA041)); // AA30 mov al, byte ptr [0xa041]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // AA33 sub ah, ah
            m.ax = m.add(u16, m.ax, 0xB); // AA35 add ax, 0xb
            continue :sw 0xAA77; // AA38 jmp 0xaa77
        },
        0xAA3A => {
            m.mark(0xAA3A);
            m.di = m.sub(u16, m.di, 0x2); // AA3A sub di, 2
            m.bx = m.di; // AA3D mov bx, di
            m.bx = m.add(u16, m.bx, m.si); // AA3F add bx, si
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), 0x0); // AA41 cmp byte ptr [bx + 0xab6], 0
            if (!m.zf) continue :sw 0xAA4B; // AA46 jne 0xaa4b
            continue :sw 0xA9B3; // AA48 jmp 0xa9b3
        },
        0xAA4B => {
            m.mark(0xAA4B);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // AA4B cmp byte ptr [di - 0x610a], 7
            if (m.sf != m.of) continue :sw 0xAA55; // AA50 jl 0xaa55
            continue :sw 0xA9B3; // AA52 jmp 0xa9b3
        },
        0xAA55 => {
            m.mark(0xAA55);
            m.setAl(m.rb(m.bx +% 0x0AB6)); // AA55 mov al, byte ptr [bx + 0xab6]
            m.cbw(); // AA59 cbw
            m.si = m.ax; // AA5A mov si, ax
            continue :sw 0xAA5C; // falls through
        },
        0xAA5C => {
            m.mark(0xAA5C);
            m.di = m.add(u16, m.di, m.si); // AA5C add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // AA5E cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xAA5C; // AA63 je 0xaa5c
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.di); // AA65 cmp word ptr [bp - 0xc], di
            if (m.zf) continue :sw 0xAA6D; // AA68 je 0xaa6d
            continue :sw 0xA9B3; // AA6A jmp 0xa9b3
        },
        0xAA6D => {
            m.mark(0xAA6D);
            m.si = m.di; // AA6D mov si, di
            m.setAl(m.rb(0xA041)); // AA6F mov al, byte ptr [0xa041]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // AA72 sub ah, ah
            m.ax = m.add(u16, m.ax, 0x9); // AA74 add ax, 9
            continue :sw 0xAA77; // falls through
        },
        0xAA77 => {
            m.mark(0xAA77);
            m.di = m.ax; // AA77 mov di, ax
            m.wb(m.si +% 0x9EF6, 0x0); // AA79 mov byte ptr [si - 0x610a], 0
            m.bx = m.di; // AA7E mov bx, di
            m.cmp(u8, m.rb(m.bx +% 0x9EF6), 0x0); // AA80 cmp byte ptr [bx - 0x610a], 0
            if (m.zf) continue :sw 0xAA9A; // AA85 je 0xaa9a
            continue :sw 0xAA87; // falls through
        },
        0xAA87 => {
            m.mark(0xAA87);
            m.push(0x1B); // AA87 push 0x1b
            m.push(m.di); // AA89 push di
            m.far(.see_black, 0xAA8A); // AA8A lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // AA8F or ax, ax
            if (!m.zf and m.sf == m.of) continue :sw 0xAA96; // AA91 jg 0xaa96
            continue :sw 0xA9AE; // AA93 jmp 0xa9ae
        },
        0xAA96 => {
            m.mark(0xAA96);
            continue :sw 0xAB52; // AA96 jmp 0xab52
        },
        0xAA9A => {
            m.mark(0xAA9A);
            m.push(0x1B); // AA9A push 0x1b
            m.push(m.di); // AA9C push di
            m.far(.see_black, 0xAA9D); // AA9D lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // AAA2 or ax, ax
            if (m.sf != m.of) continue :sw 0xAAA9; // AAA4 jl 0xaaa9
            continue :sw 0xA11A; // AAA6 jmp 0xa11a
        },
        0xAAA9 => {
            m.mark(0xAAA9);
            continue :sw 0xA9AE; // AAA9 jmp 0xa9ae
        },
        0xAAAC => {
            m.mark(0xAAAC);
            m.@"test"(u16, m.si, 0x1); // AAAC test si, 1
            if (m.zf) continue :sw 0xAB12; // AAB0 je 0xab12
            m.setAl(m.rb(0xA041)); // AAB2 mov al, byte ptr [0xa041]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // AAB5 sub ah, ah
            m.di = m.ax; // AAB7 mov di, ax
            m.di = m.add(u16, m.di, 0xB); // AAB9 add di, 0xb
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // AABC cmp byte ptr [di - 0x610a], 7
            if (m.sf != m.of) continue :sw 0xAAC6; // AAC1 jl 0xaac6
            continue :sw 0xAB94; // AAC3 jmp 0xab94
        },
        0xAAC6 => {
            m.mark(0xAAC6);
            m.si = m.di; // AAC6 mov si, di
            continue :sw 0xAAC8; // falls through
        },
        0xAAC8 => {
            m.mark(0xAAC8);
            m.si = m.add(u16, m.si, 0xA); // AAC8 add si, 0xa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // AACB cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xAAC8; // AAD0 je 0xaac8
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // AAD2 cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xAADA; // AAD5 je 0xaada
            continue :sw 0xAB94; // AAD7 jmp 0xab94
        },
        0xAADA => {
            m.mark(0xAADA);
            m.wb(m.si +% 0x9EF6, 0x0); // AADA mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // AADF cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xAB46; // AAE4 jne 0xab46
            m.push(0x1B); // AAE6 push 0x1b
            m.push(m.di); // AAE8 push di
            m.far(.see_black, 0xAAE9); // AAE9 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // AAEE or ax, ax
            if (m.sf != m.of) continue :sw 0xAAF5; // AAF0 jl 0xaaf5
            continue :sw 0xA11A; // AAF2 jmp 0xa11a
        },
        0xAAF5 => {
            m.mark(0xAAF5);
            m.di = m.sub(u16, m.di, 0xA); // AAF5 sub di, 0xa
            continue :sw 0xAAF8; // falls through
        },
        0xAAF8 => {
            m.mark(0xAAF8);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // AAF8 cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xAB79; // AAFD jne 0xab79
            continue :sw 0xAAFF; // falls through
        },
        0xAAFF => {
            m.mark(0xAAFF);
            m.push(0x1B); // AAFF push 0x1b
            m.push(m.di); // AB01 push di
            m.far(.see_black, 0xAB02); // AB02 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // AB07 or ax, ax
            if (m.sf == m.of) continue :sw 0xAB0E; // AB09 jge 0xab0e
            continue :sw 0xAB8F; // AB0B jmp 0xab8f
        },
        0xAB0E => {
            m.mark(0xAB0E);
            continue :sw 0xA11A; // AB0E jmp 0xa11a
        },
        0xAB12 => {
            m.mark(0xAB12);
            m.@"test"(u16, m.si, 0x4); // AB12 test si, 4
            if (m.zf) continue :sw 0xAB94; // AB16 je 0xab94
            m.setAl(m.rb(0xA041)); // AB18 mov al, byte ptr [0xa041]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // AB1B sub ah, ah
            m.di = m.ax; // AB1D mov di, ax
            m.di = m.add(u16, m.di, 0x9); // AB1F add di, 9
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // AB22 cmp byte ptr [di - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xAB94; // AB27 jge 0xab94
            m.si = m.di; // AB29 mov si, di
            continue :sw 0xAB2B; // falls through
        },
        0xAB2B => {
            m.mark(0xAB2B);
            m.si = m.add(u16, m.si, 0xA); // AB2B add si, 0xa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // AB2E cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xAB2B; // AB33 je 0xab2b
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // AB35 cmp word ptr [bp - 0xc], si
            if (!m.zf) continue :sw 0xAB94; // AB38 jne 0xab94
            m.wb(m.si +% 0x9EF6, 0x0); // AB3A mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // AB3F cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xAB60; // AB44 je 0xab60
            continue :sw 0xAB46; // falls through
        },
        0xAB46 => {
            m.mark(0xAB46);
            m.push(0x1B); // AB46 push 0x1b
            m.push(m.di); // AB48 push di
            m.far(.see_black, 0xAB49); // AB49 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // AB4E or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xAB8F; // AB50 jle 0xab8f
            continue :sw 0xAB52; // falls through
        },
        0xAB52 => {
            m.mark(0xAB52);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x1); // AB52 cmp byte ptr [di - 0x610a], 1
            continue :sw 0xAB57; // falls through
        },
        0xAB57 => {
            m.mark(0xAB57);
            if (m.zf) continue :sw 0xAB5C; // AB57 je 0xab5c
            continue :sw 0xA11D; // AB59 jmp 0xa11d
        },
        0xAB5C => {
            m.mark(0xAB5C);
            continue :sw 0xA11A; // AB5C jmp 0xa11a
        },
        0xAB60 => {
            m.mark(0xAB60);
            m.push(0x1B); // AB60 push 0x1b
            m.push(m.di); // AB62 push di
            m.far(.see_black, 0xAB63); // AB63 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // AB68 or ax, ax
            if (m.sf != m.of) continue :sw 0xAB6F; // AB6A jl 0xab6f
            continue :sw 0xA11A; // AB6C jmp 0xa11a
        },
        0xAB6F => {
            m.mark(0xAB6F);
            m.di = m.sub(u16, m.di, 0xA); // AB6F sub di, 0xa
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // AB72 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xAAFF; // AB77 je 0xaaff
            continue :sw 0xAB79; // falls through
        },
        0xAB79 => {
            m.mark(0xAB79);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // AB79 cmp byte ptr [di - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xAB8F; // AB7E jge 0xab8f
            continue :sw 0xAB80; // falls through
        },
        0xAB80 => {
            m.mark(0xAB80);
            m.push(0x1B); // AB80 push 0x1b
            m.push(m.di); // AB82 push di
            m.far(.see_black, 0xAB83); // AB83 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // AB88 or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xAB8F; // AB8A jle 0xab8f
            continue :sw 0xA11D; // AB8C jmp 0xa11d
        },
        0xAB8F => {
            m.mark(0xAB8F);
            m.wb(m.si +% 0x9EF6, 0xC); // AB8F mov byte ptr [si - 0x610a], 0xc
            continue :sw 0xAB94; // falls through
        },
        0xAB94 => {
            m.mark(0xAB94);
            m.setAl(m.rb(0xA041)); // AB94 mov al, byte ptr [0xa041]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // AB97 sub ah, ah
            m.di = m.ax; // AB99 mov di, ax
            continue :sw 0xAB9B; // falls through
        },
        0xAB9B => {
            m.mark(0xAB9B);
            m.cmp(u16, m.di, 0x1C); // AB9B cmp di, 0x1c
            if (m.zf or m.sf != m.of) continue :sw 0xAC10; // AB9E jle 0xac10
            m.cmp(u8, m.rb(m.di +% 0x9EEC), 0x0); // ABA0 cmp byte ptr [di - 0x6114], 0
            if (m.zf) continue :sw 0xABAA; // ABA5 je 0xabaa
            continue :sw 0xAD90; // ABA7 jmp 0xad90
        },
        0xABAA => {
            m.mark(0xABAA);
            m.cmp(u8, m.rb(0xA04E), 0x1C); // ABAA cmp byte ptr [0xa04e], 0x1c
            if (m.cf or m.zf) continue :sw 0xABBB; // ABAF jbe 0xabbb
            m.cmp(u8, m.rb(0xA04F), 0x1C); // ABB1 cmp byte ptr [0xa04f], 0x1c
            if (m.cf or m.zf) continue :sw 0xABBB; // ABB6 jbe 0xabbb
            continue :sw 0xAD90; // ABB8 jmp 0xad90
        },
        0xABBB => {
            m.mark(0xABBB);
            m.cmp(u16, m.di, 0x25); // ABBB cmp di, 0x25
            if (m.sf != m.of) continue :sw 0xABF8; // ABBE jl 0xabf8
            m.si = m.di +% 0xFFF5; // ABC0 lea si, [di - 0xb]
            continue :sw 0xABC7; // ABC3 jmp 0xabc7
        },
        0xABC6 => {
            m.mark(0xABC6);
            m.si = m.dec(u16, m.si); // ABC6 dec si
            continue :sw 0xABC7; // falls through
        },
        0xABC7 => {
            m.mark(0xABC7);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // ABC7 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xABC6; // ABCC je 0xabc6
            continue :sw 0xABCE; // falls through
        },
        0xABCE => {
            m.mark(0xABCE);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xB); // ABCE cmp byte ptr [si - 0x610a], 0xb
            if (m.zf) continue :sw 0xABD8; // ABD3 je 0xabd8
            continue :sw 0xAD90; // ABD5 jmp 0xad90
        },
        0xABD8 => {
            m.mark(0xABD8);
            m.wb(m.si +% 0x9EF6, 0x0); // ABD8 mov byte ptr [si - 0x610a], 0
            m.push(0xF); // ABDD push 0xf
            m.ax = m.di +% 0xFFF6; // ABDF lea ax, [di - 0xa]
            m.push(m.ax); // ABE2 push ax
            continue :sw 0xABE3; // falls through
        },
        0xABE3 => {
            m.mark(0xABE3);
            m.far(.see_black, 0xABE3); // ABE3 lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // ABE8 or ax, ax
            if (m.sf != m.of) continue :sw 0xABEF; // ABEA jl 0xabef
            continue :sw 0xA49A; // ABEC jmp 0xa49a
        },
        0xABEF => {
            m.mark(0xABEF);
            m.wb(m.si +% 0x9EF6, 0xB); // ABEF mov byte ptr [si - 0x610a], 0xb
            continue :sw 0xAD90; // ABF4 jmp 0xad90
        },
        0xABF8 => {
            m.mark(0xABF8);
            m.cmp(u16, m.di, 0x20); // ABF8 cmp di, 0x20
            if (m.zf or m.sf != m.of) continue :sw 0xAC00; // ABFB jle 0xac00
            continue :sw 0xAD90; // ABFD jmp 0xad90
        },
        0xAC00 => {
            m.mark(0xAC00);
            m.si = m.di +% 0xFFF7; // AC00 lea si, [di - 9]
            continue :sw 0xAC07; // AC03 jmp 0xac07
        },
        0xAC06 => {
            m.mark(0xAC06);
            m.si = m.inc(u16, m.si); // AC06 inc si
            continue :sw 0xAC07; // falls through
        },
        0xAC07 => {
            m.mark(0xAC07);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // AC07 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xAC06; // AC0C je 0xac06
            continue :sw 0xABCE; // AC0E jmp 0xabce
        },
        0xAC10 => {
            m.mark(0xAC10);
            m.di = m.add(u16, m.di, 0xA); // AC10 add di, 0xa
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // AC13 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xAC5E; // AC18 je 0xac5e
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // AC1A cmp byte ptr [di - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xAC5E; // AC1F jge 0xac5e
            m.setAl(m.rb(0xA22E)); // AC21 mov al, byte ptr [0xa22e]
            m.cbw(); // AC24 cbw
            m.bx = m.ax; // AC25 mov bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x9EA8), 0x0); // AC27 cmp byte ptr [bx - 0x6158], 0
            if (!m.zf) continue :sw 0xAC5E; // AC2C jne 0xac5e
            m.si = m.di +% 0x000A; // AC2E lea si, [di + 0xa]
            continue :sw 0xAC37; // AC31 jmp 0xac37
        },
        0xAC34 => {
            m.mark(0xAC34);
            m.si = m.add(u16, m.si, 0xA); // AC34 add si, 0xa
            continue :sw 0xAC37; // falls through
        },
        0xAC37 => {
            m.mark(0xAC37);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // AC37 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xAC34; // AC3C je 0xac34
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xB); // AC3E cmp byte ptr [si - 0x610a], 0xb
            if (!m.zf) continue :sw 0xAC5E; // AC43 jne 0xac5e
            m.wb(m.si +% 0x9EF6, 0x0); // AC45 mov byte ptr [si - 0x610a], 0
            m.push(0xF); // AC4A push 0xf
            m.push(m.di); // AC4C push di
            m.far(.see_black, 0xAC4D); // AC4D lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // AC52 or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xAC59; // AC54 jle 0xac59
            continue :sw 0xA49A; // AC56 jmp 0xa49a
        },
        0xAC59 => {
            m.mark(0xAC59);
            m.wb(m.si +% 0x9EF6, 0xB); // AC59 mov byte ptr [si - 0x610a], 0xb
            continue :sw 0xAC5E; // falls through
        },
        0xAC5E => {
            m.mark(0xAC5E);
            m.di = m.sub(u16, m.di, 0x9); // AC5E sub di, 9
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // AC61 cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xAC9E; // AC66 jne 0xac9e
            m.si = m.di; // AC68 mov si, di
            continue :sw 0xAC6A; // falls through
        },
        0xAC6A => {
            m.mark(0xAC6A);
            m.si = m.add(u16, m.si, 0xA); // AC6A add si, 0xa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // AC6D cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xAC6A; // AC72 je 0xac6a
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xB); // AC74 cmp byte ptr [si - 0x610a], 0xb
            if (!m.zf) continue :sw 0xAC9E; // AC79 jne 0xac9e
            m.wb(m.si +% 0x9EF6, 0x0); // AC7B mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // AC80 cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xAC8A; // AC85 je 0xac8a
            continue :sw 0xA49A; // AC87 jmp 0xa49a
        },
        0xAC8A => {
            m.mark(0xAC8A);
            m.push(0xF); // AC8A push 0xf
            m.push(m.di); // AC8C push di
            m.far(.see_black, 0xAC8D); // AC8D lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // AC92 or ax, ax
            if (m.sf != m.of) continue :sw 0xAC99; // AC94 jl 0xac99
            continue :sw 0xA49A; // AC96 jmp 0xa49a
        },
        0xAC99 => {
            m.mark(0xAC99);
            m.wb(m.si +% 0x9EF6, 0xB); // AC99 mov byte ptr [si - 0x610a], 0xb
            continue :sw 0xAC9E; // falls through
        },
        0xAC9E => {
            m.mark(0xAC9E);
            m.di = m.sub(u16, m.di, 0x2); // AC9E sub di, 2
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // ACA1 cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xACDE; // ACA6 jne 0xacde
            m.si = m.di; // ACA8 mov si, di
            continue :sw 0xACAA; // falls through
        },
        0xACAA => {
            m.mark(0xACAA);
            m.si = m.add(u16, m.si, 0xA); // ACAA add si, 0xa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // ACAD cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xACAA; // ACB2 je 0xacaa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xB); // ACB4 cmp byte ptr [si - 0x610a], 0xb
            if (!m.zf) continue :sw 0xACDE; // ACB9 jne 0xacde
            m.wb(m.si +% 0x9EF6, 0x0); // ACBB mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // ACC0 cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xACCA; // ACC5 je 0xacca
            continue :sw 0xA49A; // ACC7 jmp 0xa49a
        },
        0xACCA => {
            m.mark(0xACCA);
            m.push(0xF); // ACCA push 0xf
            m.push(m.di); // ACCC push di
            m.far(.see_black, 0xACCD); // ACCD lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // ACD2 or ax, ax
            if (m.sf != m.of) continue :sw 0xACD9; // ACD4 jl 0xacd9
            continue :sw 0xA49A; // ACD6 jmp 0xa49a
        },
        0xACD9 => {
            m.mark(0xACD9);
            m.wb(m.si +% 0x9EF6, 0xB); // ACD9 mov byte ptr [si - 0x610a], 0xb
            continue :sw 0xACDE; // falls through
        },
        0xACDE => {
            m.mark(0xACDE);
            m.cmp(u8, m.rb(0xA04E), 0x26); // ACDE cmp byte ptr [0xa04e], 0x26
            if (!m.cf and !m.zf) continue :sw 0xACEC; // ACE3 ja 0xacec
            m.cmp(u8, m.rb(0xA04E), 0x1F); // ACE5 cmp byte ptr [0xa04e], 0x1f
            if (!m.cf) continue :sw 0xAD00; // ACEA jae 0xad00
            continue :sw 0xACEC; // falls through
        },
        0xACEC => {
            m.mark(0xACEC);
            m.cmp(u8, m.rb(0xA04F), 0x26); // ACEC cmp byte ptr [0xa04f], 0x26
            if (m.cf or m.zf) continue :sw 0xACF6; // ACF1 jbe 0xacf6
            continue :sw 0xAD90; // ACF3 jmp 0xad90
        },
        0xACF6 => {
            m.mark(0xACF6);
            m.cmp(u8, m.rb(0xA04F), 0x1F); // ACF6 cmp byte ptr [0xa04f], 0x1f
            if (!m.cf) continue :sw 0xAD00; // ACFB jae 0xad00
            continue :sw 0xAD90; // ACFD jmp 0xad90
        },
        0xAD00 => {
            m.mark(0xAD00);
            m.di = m.add(u16, m.di, 0xB); // AD00 add di, 0xb
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // AD03 cmp byte ptr [di - 0x610a], 7
            if (m.sf != m.of) continue :sw 0xAD0D; // AD08 jl 0xad0d
            continue :sw 0xAD90; // AD0A jmp 0xad90
        },
        0xAD0D => {
            m.mark(0xAD0D);
            m.si = m.di; // AD0D mov si, di
            continue :sw 0xAD0F; // falls through
        },
        0xAD0F => {
            m.mark(0xAD0F);
            m.si = m.inc(u16, m.si); // AD0F inc si
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // AD10 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xAD0F; // AD15 je 0xad0f
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xB); // AD17 cmp byte ptr [si - 0x610a], 0xb
            if (!m.zf) continue :sw 0xAD4E; // AD1C jne 0xad4e
            m.wb(m.si +% 0x9EF6, 0x0); // AD1E mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // AD23 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xAD3A; // AD28 je 0xad3a
            m.push(0xF); // AD2A push 0xf
            m.push(m.di); // AD2C push di
            m.far(.see_black, 0xAD2D); // AD2D lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // AD32 or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xAD49; // AD34 jle 0xad49
            continue :sw 0xA49A; // AD36 jmp 0xa49a
        },
        0xAD3A => {
            m.mark(0xAD3A);
            m.push(0xF); // AD3A push 0xf
            m.push(m.di); // AD3C push di
            m.far(.see_black, 0xAD3D); // AD3D lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // AD42 or ax, ax
            if (m.sf != m.of) continue :sw 0xAD49; // AD44 jl 0xad49
            continue :sw 0xA49A; // AD46 jmp 0xa49a
        },
        0xAD49 => {
            m.mark(0xAD49);
            m.wb(m.si +% 0x9EF6, 0xB); // AD49 mov byte ptr [si - 0x610a], 0xb
            continue :sw 0xAD4E; // falls through
        },
        0xAD4E => {
            m.mark(0xAD4E);
            m.si = m.di; // AD4E mov si, di
            continue :sw 0xAD50; // falls through
        },
        0xAD50 => {
            m.mark(0xAD50);
            m.si = m.dec(u16, m.si); // AD50 dec si
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // AD51 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xAD50; // AD56 je 0xad50
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xB); // AD58 cmp byte ptr [si - 0x610a], 0xb
            if (!m.zf) continue :sw 0xAD90; // AD5D jne 0xad90
            m.wb(m.si +% 0x9EF6, 0x0); // AD5F mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // AD64 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xAD7E; // AD69 je 0xad7e
            m.push(0xF); // AD6B push 0xf
            m.push(m.di); // AD6D push di
            m.far(.see_black, 0xAD6E); // AD6E lcall 0x2b9f, 0xcac2
            m.ax = m.@"or"(u16, m.ax, m.ax); // AD73 or ax, ax
            if (!m.zf and m.sf == m.of) continue :sw 0xAD7A; // AD75 jg 0xad7a
            continue :sw 0xABEF; // AD77 jmp 0xabef
        },
        0xAD7A => {
            m.mark(0xAD7A);
            continue :sw 0xA49A; // AD7A jmp 0xa49a
        },
        0xAD7E => {
            m.mark(0xAD7E);
            m.push(0xF); // AD7E push 0xf
            m.push(m.di); // AD80 push di
            continue :sw 0xABE3; // AD81 jmp 0xabe3
        },
        0xAD84 => {
            m.mark(0xAD84);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x3C)); // AD84 sub word ptr [bp - 4], 0x3c
            continue :sw 0xAD88; // falls through
        },
        0xAD88 => {
            m.mark(0xAD88);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x1E)); // AD88 sub word ptr [bp - 2], 0x1e
            continue :sw 0xAD8C; // falls through
        },
        0xAD8C => {
            m.mark(0xAD8C);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x1E)); // AD8C sub word ptr [bp - 2], 0x1e
            continue :sw 0xAD90; // falls through
        },
        0xAD90 => {
            m.mark(0xAD90);
            m.cmp(u8, m.rb(0x931A), 0x0); // AD90 cmp byte ptr [0x931a], 0
            if (!m.zf) continue :sw 0xADCC; // AD95 jne 0xadcc
            continue :sw 0xAD97; // falls through
        },
        0xAD97 => {
            m.mark(0xAD97);
            m.ax = m.rw(m.bp +% 0xFFFE); // AD97 mov ax, word ptr [bp - 2]
            m.si = m.pop(); // AD9A pop si
            m.di = m.pop(); // AD9B pop di
            m.sp = m.bp;
            m.bp = m.pop(); // AD9C leave
            return; // AD9D retf
        },
        0xAD9E => {
            m.mark(0xAD9E);
            m.ax = m.rw(0xA272); // AD9E mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // ADA1 cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xADBD; // ADA4 jle 0xadbd
            m.cmp(u8, m.rb(0xA40E), 0x0); // ADA6 cmp byte ptr [0xa40e], 0
            if (!m.zf) continue :sw 0xADBD; // ADAB jne 0xadbd
            m.ax = m.rw(0x9356); // ADAD mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // ADB0 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xAD88; // ADB3 jg 0xad88
            m.cmp(u16, m.rw(0xAE3A), 0xED8); // ADB5 cmp word ptr [0xae3a], 0xed8
            if (!m.zf and m.sf == m.of) continue :sw 0xAD88; // ADBB jg 0xad88
            continue :sw 0xADBD; // falls through
        },
        0xADBD => {
            m.mark(0xADBD);
            m.bx = m.rw(m.bp +% 0x000A); // ADBD mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // ADC0 inc byte ptr [bx]
            m.ax = m.rw(m.bp +% 0xFFFE); // ADC2 mov ax, word ptr [bp - 2]
            m.ax = m.sub(u16, m.ax, 0x1388); // ADC5 sub ax, 0x1388
            m.si = m.pop(); // ADC8 pop si
            m.di = m.pop(); // ADC9 pop di
            m.sp = m.bp;
            m.bp = m.pop(); // ADCA leave
            return; // ADCB retf
        },
        0xADCC => {
            m.mark(0xADCC);
            m.cmp(u16, m.rw(0x378E), 0x1838); // ADCC cmp word ptr [0x378e], 0x1838
            if (!m.cf) continue :sw 0xADD7; // ADD2 jae 0xadd7
            continue :sw 0xAE86; // ADD4 jmp 0xae86
        },
        0xADD7 => {
            m.mark(0xADD7);
            m.cmp(u8, m.rb(0x9F37), 0x1); // ADD7 cmp byte ptr [0x9f37], 1
            if (!m.zf) continue :sw 0xAE2A; // ADDC jne 0xae2a
            m.cmp(u8, m.rb(0xA55D), 0x0); // ADDE cmp byte ptr [0xa55d], 0
            if (!m.zf) continue :sw 0xAE2A; // ADE3 jne 0xae2a
            m.cmp(u8, m.rb(0x381B), 0x0); // ADE5 cmp byte ptr [0x381b], 0
            if (!m.zf) continue :sw 0xAE14; // ADEA jne 0xae14
            m.bx = 0xAA9; // ADEC mov bx, 0xaa9
            m.setAl(m.rb(0xA04B)); // ADEF mov al, byte ptr [0xa04b]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // ADF2 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // ADF4 sub bx, ax
            m.setAl(m.rb(m.bx)); // ADF6 mov al, byte ptr [bx]
            m.bx = 0xAA9; // ADF8 mov bx, 0xaa9
            m.setCl(m.rb(0xA04A)); // ADFB mov cl, byte ptr [0xa04a]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // ADFF sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // AE01 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx))); // AE03 or al, byte ptr [bx]
            if (m.zf) continue :sw 0xAE2A; // AE05 je 0xae2a
            m.push(0x6); // AE07 push 6
            m.push(0x41); // AE09 push 0x41
            m.far(.att_41b6, 0xAE0B); // AE0B lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // AE10 or ax, ax
            if (m.sf == m.of) continue :sw 0xAE2A; // AE12 jge 0xae2a
            continue :sw 0xAE14; // falls through
        },
        0xAE14 => {
            m.mark(0xAE14);
            m.ax = m.rw(0xA272); // AE14 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // AE17 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xAE26; // AE1A jg 0xae26
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x12C)); // AE1C sub word ptr [bp - 2], 0x12c
            m.bx = m.rw(m.bp +% 0x000A); // AE21 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // AE24 inc byte ptr [bx]
            continue :sw 0xAE26; // falls through
        },
        0xAE26 => {
            m.mark(0xAE26);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x28)); // AE26 sub word ptr [bp - 4], 0x28
            continue :sw 0xAE2A; // falls through
        },
        0xAE2A => {
            m.mark(0xAE2A);
            m.cmp(u8, m.rb(0x9F36), 0x1); // AE2A cmp byte ptr [0x9f36], 1
            if (m.zf) continue :sw 0xAE34; // AE2F je 0xae34
            continue :sw 0xB004; // AE31 jmp 0xb004
        },
        0xAE34 => {
            m.mark(0xAE34);
            m.cmp(u8, m.rb(0xA55C), 0x0); // AE34 cmp byte ptr [0xa55c], 0
            if (m.zf) continue :sw 0xAE3E; // AE39 je 0xae3e
            continue :sw 0xB004; // AE3B jmp 0xb004
        },
        0xAE3E => {
            m.mark(0xAE3E);
            m.cmp(u8, m.rb(0x381A), 0x0); // AE3E cmp byte ptr [0x381a], 0
            if (!m.zf) continue :sw 0xAE73; // AE43 jne 0xae73
            m.bx = 0xAA8; // AE45 mov bx, 0xaa8
            m.setAl(m.rb(0xA04B)); // AE48 mov al, byte ptr [0xa04b]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // AE4B sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // AE4D sub bx, ax
            m.setAl(m.rb(m.bx)); // AE4F mov al, byte ptr [bx]
            m.bx = 0xAA8; // AE51 mov bx, 0xaa8
            m.setCl(m.rb(0xA04A)); // AE54 mov cl, byte ptr [0xa04a]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // AE58 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // AE5A sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx))); // AE5C or al, byte ptr [bx]
            if (!m.zf) continue :sw 0xAE63; // AE5E jne 0xae63
            continue :sw 0xB004; // AE60 jmp 0xb004
        },
        0xAE63 => {
            m.mark(0xAE63);
            m.push(0x6); // AE63 push 6
            m.push(0x40); // AE65 push 0x40
            m.far(.att_41b6, 0xAE67); // AE67 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // AE6C or ax, ax
            if (m.sf != m.of) continue :sw 0xAE73; // AE6E jl 0xae73
            continue :sw 0xB004; // AE70 jmp 0xb004
        },
        0xAE73 => {
            m.mark(0xAE73);
            m.ax = m.rw(0xA272); // AE73 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // AE76 cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xAE7E; // AE79 jle 0xae7e
            continue :sw 0xB000; // AE7B jmp 0xb000
        },
        0xAE7E => {
            m.mark(0xAE7E);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x12C)); // AE7E sub word ptr [bp - 2], 0x12c
            continue :sw 0xAFFB; // AE83 jmp 0xaffb
        },
        0xAE86 => {
            m.mark(0xAE86);
            m.cmp(u8, m.rb(0x931B), 0x0); // AE86 cmp byte ptr [0x931b], 0
            if (!m.zf) continue :sw 0xAE90; // AE8B jne 0xae90
            continue :sw 0xB004; // AE8D jmp 0xb004
        },
        0xAE90 => {
            m.mark(0xAE90);
            m.cmp(u16, m.rw(0xAE3A), 0x44C); // AE90 cmp word ptr [0xae3a], 0x44c
            if (!m.zf) continue :sw 0xAEFC; // AE96 jne 0xaefc
            continue :sw 0xAE98; // falls through
        },
        0xAE98 => {
            m.mark(0xAE98);
            m.setBl(m.rb(0x8EB6)); // AE98 mov bl, byte ptr [0x8eb6]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // AE9C sub bh, bh
            m.setAl(m.rb(m.bx +% 0x01AC)); // AE9E mov al, byte ptr [bx + 0x1ac]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // AEA2 sub ah, ah
            m.di = m.ax; // AEA4 mov di, ax
            m.di = m.@"or"(u16, m.di, m.di); // AEA6 or di, di
            if (!m.zf) continue :sw 0xAEAD; // AEA8 jne 0xaead
            continue :sw 0xB004; // AEAA jmp 0xb004
        },
        0xAEAD => {
            m.mark(0xAEAD);
            m.setAl(m.rb(m.di +% 0x019C)); // AEAD mov al, byte ptr [di + 0x19c]
            m.wb(0x8EB6, m.@"and"(u8, m.rb(0x8EB6), m.al())); // AEB1 and byte ptr [0x8eb6], al
            m.setAl(m.rb(m.di +% 0xA03A)); // AEB5 mov al, byte ptr [di - 0x5fc6]
            m.di = m.ax; // AEB9 mov di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x1); // AEBB cmp byte ptr [di - 0x610a], 1
            if (!m.zf) continue :sw 0xAE98; // AEC0 jne 0xae98
            m.si = m.di +% 0x00B0; // AEC2 lea si, [di + 0xb0]
            m.bx = m.si; // AEC6 mov bx, si
            m.setAl(m.rb(0xA04E)); // AEC8 mov al, byte ptr [0xa04e]
            m.bx = m.sub(u16, m.bx, m.ax); // AECB sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0BB4)); // AECD mov al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // AED1 mov bx, si
            m.setCl(m.rb(0xA04F)); // AED3 mov cl, byte ptr [0xa04f]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // AED7 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // AED9 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // AEDB or al, byte ptr [bx + 0xbb4]
            if (m.zf) continue :sw 0xAE98; // AEDF je 0xae98
            m.push(0x6); // AEE1 push 6
            m.push(m.di); // AEE3 push di
            m.far(.att_41b6, 0xAEE4); // AEE4 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // AEE9 or ax, ax
            if (m.sf == m.of) continue :sw 0xAE98; // AEEB jge 0xae98
            m.ax = m.rw(0x9356); // AEED mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // AEF0 cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xAEF8; // AEF3 jl 0xaef8
            continue :sw 0xB000; // AEF5 jmp 0xb000
        },
        0xAEF8 => {
            m.mark(0xAEF8);
            continue :sw 0xAFE6; // AEF8 jmp 0xafe6
        },
        0xAEFC => {
            m.mark(0xAEFC);
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), 0x62); // AEFC cmp word ptr [bp - 0xc], 0x62
            if (!m.zf and m.sf == m.of) continue :sw 0xAF05; // AF00 jg 0xaf05
            continue :sw 0xAF90; // AF02 jmp 0xaf90
        },
        0xAF05 => {
            m.mark(0xAF05);
            m.setBl(m.rb(0x8EB6)); // AF05 mov bl, byte ptr [0x8eb6]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // AF09 sub bh, bh
            m.setAl(m.rb(m.bx +% 0x01AC)); // AF0B mov al, byte ptr [bx + 0x1ac]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // AF0F sub ah, ah
            m.di = m.ax; // AF11 mov di, ax
            m.di = m.@"or"(u16, m.di, m.di); // AF13 or di, di
            if (!m.zf) continue :sw 0xAF1A; // AF15 jne 0xaf1a
            continue :sw 0xB004; // AF17 jmp 0xb004
        },
        0xAF1A => {
            m.mark(0xAF1A);
            m.setAl(m.rb(m.di +% 0x019C)); // AF1A mov al, byte ptr [di + 0x19c]
            m.wb(0x8EB6, m.@"and"(u8, m.rb(0x8EB6), m.al())); // AF1E and byte ptr [0x8eb6], al
            m.setAl(m.rb(m.di +% 0xA03A)); // AF22 mov al, byte ptr [di - 0x5fc6]
            m.di = m.ax; // AF26 mov di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x1); // AF28 cmp byte ptr [di - 0x610a], 1
            if (!m.zf) continue :sw 0xAF05; // AF2D jne 0xaf05
            m.si = m.di +% 0x00B0; // AF2F lea si, [di + 0xb0]
            m.bx = m.si; // AF33 mov bx, si
            m.setAl(m.rb(0xA04E)); // AF35 mov al, byte ptr [0xa04e]
            m.bx = m.sub(u16, m.bx, m.ax); // AF38 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0BB4)); // AF3A mov al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // AF3E mov bx, si
            m.setCl(m.rb(0xA04F)); // AF40 mov cl, byte ptr [0xa04f]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // AF44 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // AF46 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // AF48 or al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // AF4C mov bx, si
            m.setCl(m.rb(0xA04C)); // AF4E mov cl, byte ptr [0xa04c]
            m.bx = m.sub(u16, m.bx, m.cx); // AF52 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // AF54 or al, byte ptr [bx + 0xab6]
            m.bx = m.si; // AF58 mov bx, si
            m.setCl(m.rb(0xA04D)); // AF5A mov cl, byte ptr [0xa04d]
            m.bx = m.sub(u16, m.bx, m.cx); // AF5E sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // AF60 or al, byte ptr [bx + 0xab6]
            m.bx = m.si; // AF64 mov bx, si
            m.setCl(m.rb(0xA04A)); // AF66 mov cl, byte ptr [0xa04a]
            m.bx = m.sub(u16, m.bx, m.cx); // AF6A sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // AF6C or al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // AF70 mov bx, si
            m.setCl(m.rb(0xA04B)); // AF72 mov cl, byte ptr [0xa04b]
            m.bx = m.sub(u16, m.bx, m.cx); // AF76 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // AF78 or al, byte ptr [bx + 0x9b8]
            if (m.zf) continue :sw 0xAF05; // AF7C je 0xaf05
            m.push(0x6); // AF7E push 6
            m.push(m.di); // AF80 push di
            m.far(.att_41b6, 0xAF81); // AF81 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // AF86 or ax, ax
            if (m.sf != m.of) continue :sw 0xAF8D; // AF88 jl 0xaf8d
            continue :sw 0xAF05; // AF8A jmp 0xaf05
        },
        0xAF8D => {
            m.mark(0xAF8D);
            continue :sw 0xAFDE; // AF8D jmp 0xafde
        },
        0xAF90 => {
            m.mark(0xAF90);
            m.cmp(u16, m.rw(0xAE3A), 0x7D0); // AF90 cmp word ptr [0xae3a], 0x7d0
            if (!m.zf) continue :sw 0xB004; // AF96 jne 0xb004
            continue :sw 0xAF98; // falls through
        },
        0xAF98 => {
            m.mark(0xAF98);
            m.setBl(m.rb(0x8EB6)); // AF98 mov bl, byte ptr [0x8eb6]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // AF9C sub bh, bh
            m.setAl(m.rb(m.bx +% 0x01AC)); // AF9E mov al, byte ptr [bx + 0x1ac]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // AFA2 sub ah, ah
            m.di = m.ax; // AFA4 mov di, ax
            m.di = m.@"or"(u16, m.di, m.di); // AFA6 or di, di
            if (m.zf) continue :sw 0xB004; // AFA8 je 0xb004
            m.setAl(m.rb(m.di +% 0x019C)); // AFAA mov al, byte ptr [di + 0x19c]
            m.wb(0x8EB6, m.@"and"(u8, m.rb(0x8EB6), m.al())); // AFAE and byte ptr [0x8eb6], al
            m.setAl(m.rb(m.di +% 0xA03A)); // AFB2 mov al, byte ptr [di - 0x5fc6]
            m.di = m.ax; // AFB6 mov di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x1); // AFB8 cmp byte ptr [di - 0x610a], 1
            if (!m.zf) continue :sw 0xAF98; // AFBD jne 0xaf98
            m.si = m.di +% 0x00B0; // AFBF lea si, [di + 0xb0]
            m.bx = m.si; // AFC3 mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // AFC5 sub bx, word ptr [bp - 0xc]
            m.setAl(m.rb(m.bx +% 0x0BB4)); // AFC8 mov al, byte ptr [bx + 0xbb4]
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // AFCC or al, byte ptr [bx + 0xab6]
            if (m.zf) continue :sw 0xAF98; // AFD0 je 0xaf98
            m.push(0x6); // AFD2 push 6
            m.push(m.di); // AFD4 push di
            m.far(.att_41b6, 0xAFD5); // AFD5 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // AFDA or ax, ax
            if (m.sf == m.of) continue :sw 0xAF98; // AFDC jge 0xaf98
            continue :sw 0xAFDE; // falls through
        },
        0xAFDE => {
            m.mark(0xAFDE);
            m.ax = m.rw(0xA272); // AFDE mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // AFE1 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xB000; // AFE4 jg 0xb000
            continue :sw 0xAFE6; // falls through
        },
        0xAFE6 => {
            m.mark(0xAFE6);
            m.cmp(u16, m.di, 0x30); // AFE6 cmp di, 0x30
            if (!m.zf and m.sf == m.of) continue :sw 0xAFF6; // AFE9 jg 0xaff6
            m.cmp(u8, m.rb(m.di +% 0x9F00), 0x8); // AFEB cmp byte ptr [di - 0x6100], 8
            if (!m.zf) continue :sw 0xAFF6; // AFF0 jne 0xaff6
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x64)); // AFF2 sub word ptr [bp - 2], 0x64
            continue :sw 0xAFF6; // falls through
        },
        0xAFF6 => {
            m.mark(0xAFF6);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // AFF6 sub word ptr [bp - 2], 0xc8
            continue :sw 0xAFFB; // falls through
        },
        0xAFFB => {
            m.mark(0xAFFB);
            m.bx = m.rw(m.bp +% 0x000A); // AFFB mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // AFFE inc byte ptr [bx]
            continue :sw 0xB000; // falls through
        },
        0xB000 => {
            m.mark(0xB000);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x28)); // B000 sub word ptr [bp - 4], 0x28
            continue :sw 0xB004; // falls through
        },
        0xB004 => {
            m.mark(0xB004);
            m.setAl(m.rb(0xA040)); // B004 mov al, byte ptr [0xa040]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // B007 sub ah, ah
            m.di = m.ax; // B009 mov di, ax
            m.cmp(u16, m.di, 0x62); // B00B cmp di, 0x62
            if (m.zf or m.sf != m.of) continue :sw 0xB02F; // B00E jle 0xb02f
            m.cmp(u8, m.rb(0xA38E), m.ah()); // B010 cmp byte ptr [0xa38e], ah
            if (!m.zf) continue :sw 0xB019; // B014 jne 0xb019
            continue :sw 0xB415; // B016 jmp 0xb415
        },
        0xB019 => {
            m.mark(0xB019);
            m.setAl(m.rb(0xA38E)); // B019 mov al, byte ptr [0xa38e]
            m.cbw(); // B01C cbw
            m.bx = m.ax; // B01D mov bx, ax
            m.setAl(m.rb(m.bx +% 0xA03A)); // B01F mov al, byte ptr [bx - 0x5fc6]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // B023 sub ah, ah
            m.di = m.ax; // B025 mov di, ax
            m.cmp(u16, m.di, 0x62); // B027 cmp di, 0x62
            if (m.zf or m.sf != m.of) continue :sw 0xB02F; // B02A jle 0xb02f
            continue :sw 0xB415; // B02C jmp 0xb415
        },
        0xB02F => {
            m.mark(0xB02F);
            m.wb(m.di +% 0x9EF6, 0x0); // B02F mov byte ptr [di - 0x610a], 0
            m.ax = m.di +% 0x00B0; // B034 lea ax, [di + 0xb0]
            m.si = m.ax; // B038 mov si, ax
            m.cmp(u8, m.rb(m.di +% 0x0E16), 0x0); // B03A cmp byte ptr [di + 0xe16], 0
            if (m.zf) continue :sw 0xB05C; // B03F je 0xb05c
            m.bx = m.ax; // B041 mov bx, ax
            m.setAl(m.rb(0xA04C)); // B043 mov al, byte ptr [0xa04c]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // B046 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // B048 sub bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), m.ah()); // B04A cmp byte ptr [bx + 0xab6], ah
            if (!m.zf) continue :sw 0xB053; // B04E jne 0xb053
            continue :sw 0xB0FC; // B050 jmp 0xb0fc
        },
        0xB053 => {
            m.mark(0xB053);
            m.cmp(u8, m.al(), 0x63); // B053 cmp al, 0x63
            if (m.cf) continue :sw 0xB05A; // B055 jb 0xb05a
            continue :sw 0xB0FC; // B057 jmp 0xb0fc
        },
        0xB05A => {
            m.mark(0xB05A);
            continue :sw 0xB072; // B05A jmp 0xb072
        },
        0xB05C => {
            m.mark(0xB05C);
            m.bx = m.si; // B05C mov bx, si
            m.setAl(m.rb(0xA04D)); // B05E mov al, byte ptr [0xa04d]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // B061 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // B063 sub bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), m.ah()); // B065 cmp byte ptr [bx + 0xab6], ah
            if (!m.zf) continue :sw 0xB06E; // B069 jne 0xb06e
            continue :sw 0xB0FC; // B06B jmp 0xb0fc
        },
        0xB06E => {
            m.mark(0xB06E);
            m.bx = m.si; // B06E mov bx, si
            m.bx = m.sub(u16, m.bx, m.ax); // B070 sub bx, ax
            continue :sw 0xB072; // falls through
        },
        0xB072 => {
            m.mark(0xB072);
            m.setAl(m.rb(m.bx +% 0x0AB6)); // B072 mov al, byte ptr [bx + 0xab6]
            m.cbw(); // B076 cbw
            m.ww(m.bp +% 0xFFF6, m.ax); // B077 mov word ptr [bp - 0xa], ax
            m.si = m.ax; // B07A mov si, ax
            m.si = m.add(u16, m.si, m.di); // B07C add si, di
            continue :sw 0xB083; // B07E jmp 0xb083
        },
        0xB080 => {
            m.mark(0xB080);
            m.si = m.add(u16, m.si, m.rw(m.bp +% 0xFFF6)); // B080 add si, word ptr [bp - 0xa]
            continue :sw 0xB083; // falls through
        },
        0xB083 => {
            m.mark(0xB083);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B083 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB080; // B088 je 0xb080
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xA); // B08A cmp byte ptr [si - 0x610a], 0xa
            if (!m.zf) continue :sw 0xB0F8; // B08F jne 0xb0f8
            m.setAl(m.rb(m.di +% 0xA09E)); // B091 mov al, byte ptr [di - 0x5f62]
            m.cbw(); // B095 cbw
            m.bx = m.ax; // B096 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // B098 mov al, byte ptr [bx + 0x490]
            m.cbw(); // B09C cbw
            m.cmp(u16, m.ax, m.rw(m.bp +% 0xFFF6)); // B09D cmp ax, word ptr [bp - 0xa]
            if (!m.zf) continue :sw 0xB0CA; // B0A0 jne 0xb0ca
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x190)); // B0A2 sub word ptr [bp - 4], 0x190
            continue :sw 0xB0A7; // falls through
        },
        0xB0A7 => {
            m.mark(0xB0A7);
            m.wb(m.di +% 0x9EF6, 0x5); // B0A7 mov byte ptr [di - 0x610a], 5
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x1F4)); // B0AC sub word ptr [bp - 2], 0x1f4
            m.ax = m.rw(0xA5EC); // B0B1 mov ax, word ptr [0xa5ec]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // B0B4 cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xB0BC; // B0B7 jl 0xb0bc
            continue :sw 0xCCA6; // B0B9 jmp 0xcca6
        },
        0xB0BC => {
            m.mark(0xB0BC);
            m.bx = m.rw(m.bp +% 0x000A); // B0BC mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // B0BF inc byte ptr [bx]
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x3E8)); // B0C1 sub word ptr [bp - 2], 0x3e8
            continue :sw 0xCCA6; // B0C6 jmp 0xcca6
        },
        0xB0CA => {
            m.mark(0xB0CA);
            m.si = m.di; // B0CA mov si, di
            continue :sw 0xB0CC; // falls through
        },
        0xB0CC => {
            m.mark(0xB0CC);
            m.si = m.sub(u16, m.si, m.rw(m.bp +% 0xFFF6)); // B0CC sub si, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B0CF cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB0CC; // B0D4 je 0xb0cc
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x4); // B0D6 cmp byte ptr [si - 0x610a], 4
            if (!m.zf) continue :sw 0xB0E0; // B0DB jne 0xb0e0
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // B0DD inc word ptr [bp - 6]
            continue :sw 0xB0E0; // falls through
        },
        0xB0E0 => {
            m.mark(0xB0E0);
            m.cmp(u16, m.rw(m.bp +% 0xFFF6), 0x0); // B0E0 cmp word ptr [bp - 0xa], 0
            if (m.sf == m.of) continue :sw 0xB0F2; // B0E4 jge 0xb0f2
            m.setAl(m.rb(m.bp +% 0xFFF6)); // B0E6 mov al, byte ptr [bp - 0xa]
            m.setAl(m.neg(u8, m.al())); // B0E9 neg al
            continue :sw 0xB0EB; // falls through
        },
        0xB0EB => {
            m.mark(0xB0EB);
            m.wb(m.bp +% 0xFFF0, m.al()); // B0EB mov byte ptr [bp - 0x10], al
            continue :sw 0xB21D; // B0EE jmp 0xb21d
        },
        0xB0F2 => {
            m.mark(0xB0F2);
            m.setAl(m.rb(m.bp +% 0xFFF6)); // B0F2 mov al, byte ptr [bp - 0xa]
            continue :sw 0xB0EB; // B0F5 jmp 0xb0eb
        },
        0xB0F8 => {
            m.mark(0xB0F8);
            m.si = m.di +% 0x00B0; // B0F8 lea si, [di + 0xb0]
            continue :sw 0xB0FC; // falls through
        },
        0xB0FC => {
            m.mark(0xB0FC);
            m.bx = m.si; // B0FC mov bx, si
            m.setAl(m.rb(0xA04E)); // B0FE mov al, byte ptr [0xa04e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // B101 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // B103 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0BB4)); // B105 mov al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // B109 mov bx, si
            m.setCl(m.rb(0xA04F)); // B10B mov cl, byte ptr [0xa04f]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // B10F sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // B111 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // B113 or al, byte ptr [bx + 0xbb4]
            if (!m.zf) continue :sw 0xB11C; // B117 jne 0xb11c
            continue :sw 0xB1C2; // B119 jmp 0xb1c2
        },
        0xB11C => {
            m.mark(0xB11C);
            m.si = m.di +% 0x000A; // B11C lea si, [di + 0xa]
            continue :sw 0xB125; // B11F jmp 0xb125
        },
        0xB122 => {
            m.mark(0xB122);
            m.si = m.add(u16, m.si, 0xA); // B122 add si, 0xa
            continue :sw 0xB125; // falls through
        },
        0xB125 => {
            m.mark(0xB125);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B125 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB122; // B12A je 0xb122
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xB); // B12C cmp byte ptr [si - 0x610a], 0xb
            if (!m.zf) continue :sw 0xB156; // B131 jne 0xb156
            m.cmp(u8, m.rb(m.di +% 0xA09E), 0x6); // B133 cmp byte ptr [di - 0x5f62], 6
            if (!m.zf) continue :sw 0xB13D; // B138 jne 0xb13d
            continue :sw 0xB0A7; // B13A jmp 0xb0a7
        },
        0xB13D => {
            m.mark(0xB13D);
            m.ax = m.rw(0xA272); // B13D mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // B140 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xB14F; // B143 jg 0xb14f
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x12C)); // B145 sub word ptr [bp - 2], 0x12c
            m.bx = m.rw(m.bp +% 0x000A); // B14A mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // B14D inc byte ptr [bx]
            continue :sw 0xB14F; // falls through
        },
        0xB14F => {
            m.mark(0xB14F);
            m.wb(m.bp +% 0xFFF0, 0xA); // B14F mov byte ptr [bp - 0x10], 0xa
            continue :sw 0xB21D; // B153 jmp 0xb21d
        },
        0xB156 => {
            m.mark(0xB156);
            m.si = m.di +% 0x0001; // B156 lea si, [di + 1]
            continue :sw 0xB15D; // B159 jmp 0xb15d
        },
        0xB15C => {
            m.mark(0xB15C);
            m.si = m.inc(u16, m.si); // B15C inc si
            continue :sw 0xB15D; // falls through
        },
        0xB15D => {
            m.mark(0xB15D);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B15D cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB15C; // B162 je 0xb15c
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xB); // B164 cmp byte ptr [si - 0x610a], 0xb
            if (!m.zf) continue :sw 0xB17C; // B169 jne 0xb17c
            m.cmp(u8, m.rb(m.di +% 0xA09E), 0x5); // B16B cmp byte ptr [di - 0x5f62], 5
            if (!m.zf) continue :sw 0xB175; // B170 jne 0xb175
            continue :sw 0xB0A7; // B172 jmp 0xb0a7
        },
        0xB175 => {
            m.mark(0xB175);
            m.wb(m.bp +% 0xFFF0, 0x1); // B175 mov byte ptr [bp - 0x10], 1
            continue :sw 0xB21D; // B179 jmp 0xb21d
        },
        0xB17C => {
            m.mark(0xB17C);
            m.si = m.di +% 0xFFFF; // B17C lea si, [di - 1]
            continue :sw 0xB183; // B17F jmp 0xb183
        },
        0xB182 => {
            m.mark(0xB182);
            m.si = m.dec(u16, m.si); // B182 dec si
            continue :sw 0xB183; // falls through
        },
        0xB183 => {
            m.mark(0xB183);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B183 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB182; // B188 je 0xb182
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xB); // B18A cmp byte ptr [si - 0x610a], 0xb
            if (!m.zf) continue :sw 0xB19C; // B18F jne 0xb19c
            m.cmp(u8, m.rb(m.di +% 0xA09E), 0x7); // B191 cmp byte ptr [di - 0x5f62], 7
            if (!m.zf) continue :sw 0xB175; // B196 jne 0xb175
            continue :sw 0xB0A7; // B198 jmp 0xb0a7
        },
        0xB19C => {
            m.mark(0xB19C);
            m.si = m.di +% 0xFFF6; // B19C lea si, [di - 0xa]
            continue :sw 0xB1A5; // B19F jmp 0xb1a5
        },
        0xB1A2 => {
            m.mark(0xB1A2);
            m.si = m.sub(u16, m.si, 0xA); // B1A2 sub si, 0xa
            continue :sw 0xB1A5; // falls through
        },
        0xB1A5 => {
            m.mark(0xB1A5);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B1A5 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB1A2; // B1AA je 0xb1a2
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xB); // B1AC cmp byte ptr [si - 0x610a], 0xb
            if (!m.zf) continue :sw 0xB1BE; // B1B1 jne 0xb1be
            m.cmp(u8, m.rb(m.di +% 0xA09E), 0x8); // B1B3 cmp byte ptr [di - 0x5f62], 8
            if (!m.zf) continue :sw 0xB14F; // B1B8 jne 0xb14f
            continue :sw 0xB0A7; // B1BA jmp 0xb0a7
        },
        0xB1BE => {
            m.mark(0xB1BE);
            m.si = m.di +% 0x00B0; // B1BE lea si, [di + 0xb0]
            continue :sw 0xB1C2; // falls through
        },
        0xB1C2 => {
            m.mark(0xB1C2);
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // B1C2 cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xB1F6; // B1C7 je 0xb1f6
            m.ww(m.bp +% 0xFFFA, 0xD); // B1C9 mov word ptr [bp - 6], 0xd
            m.ax = m.rw(0xA272); // B1CE mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // B1D1 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xB1F0; // B1D4 jg 0xb1f0
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x1F4)); // B1D6 sub word ptr [bp - 2], 0x1f4
            m.wb(m.di +% 0x9EF6, 0x5); // B1DB mov byte ptr [di - 0x610a], 5
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // B1E0 inc word ptr [bp - 6]
            m.bx = m.rw(m.bp +% 0x000A); // B1E3 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // B1E6 inc byte ptr [bx]
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x5DC)); // B1E8 sub word ptr [bp - 2], 0x5dc
            continue :sw 0xCCA6; // B1ED jmp 0xcca6
        },
        0xB1F0 => {
            m.mark(0xB1F0);
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // B1F0 inc word ptr [bp - 6]
            continue :sw 0xB219; // B1F3 jmp 0xb219
        },
        0xB1F6 => {
            m.mark(0xB1F6);
            m.bx = m.si; // B1F6 mov bx, si
            m.setAl(m.rb(0xA04A)); // B1F8 mov al, byte ptr [0xa04a]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // B1FB sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // B1FD sub bx, ax
            m.setAl(m.rb(m.bx +% 0x09B8)); // B1FF mov al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // B203 mov bx, si
            m.setCl(m.rb(0xA04B)); // B205 mov cl, byte ptr [0xa04b]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // B209 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // B20B sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // B20D or al, byte ptr [bx + 0x9b8]
            if (!m.zf) continue :sw 0xB216; // B211 jne 0xb216
            continue :sw 0xB3E0; // B213 jmp 0xb3e0
        },
        0xB216 => {
            m.mark(0xB216);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // B216 inc word ptr [bp - 8]
            continue :sw 0xB219; // falls through
        },
        0xB219 => {
            m.mark(0xB219);
            m.wb(m.bp +% 0xFFF0, 0x0); // B219 mov byte ptr [bp - 0x10], 0
            continue :sw 0xB21D; // falls through
        },
        0xB21D => {
            m.mark(0xB21D);
            m.cmp(u8, m.rb(m.bp +% 0xFFF0), 0x9); // B21D cmp byte ptr [bp - 0x10], 9
            if (m.zf) continue :sw 0xB291; // B221 je 0xb291
            m.si = m.di +% 0xFFF7; // B223 lea si, [di - 9]
            continue :sw 0xB226; // falls through
        },
        0xB226 => {
            m.mark(0xB226);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B226 cmp byte ptr [si - 0x610a], 0
            if (!m.zf) continue :sw 0xB250; // B22B jne 0xb250
            m.push(0x1B); // B22D push 0x1b
            m.push(m.si); // B22F push si
            m.far(.att_41b6, 0xB230); // B230 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B235 or ax, ax
            if (m.sf != m.of) continue :sw 0xB24A; // B237 jl 0xb24a
            continue :sw 0xB239; // falls through
        },
        0xB239 => {
            m.mark(0xB239);
            m.cmp(u8, m.rb(m.bp +% 0xFFF0), 0x0); // B239 cmp byte ptr [bp - 0x10], 0
            if (m.zf) continue :sw 0xB242; // B23D je 0xb242
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // B23F inc word ptr [bp - 8]
            continue :sw 0xB242; // falls through
        },
        0xB242 => {
            m.mark(0xB242);
            m.wb(m.di +% 0x9EF6, 0x5); // B242 mov byte ptr [di - 0x610a], 5
            continue :sw 0xB415; // B247 jmp 0xb415
        },
        0xB24A => {
            m.mark(0xB24A);
            m.si = m.sub(u16, m.si, 0x9); // B24A sub si, 9
            continue :sw 0xB226; // B24D jmp 0xb226
        },
        0xB250 => {
            m.mark(0xB250);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // B250 cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xB263; // B255 jle 0xb263
            m.push(0x1B); // B257 push 0x1b
            m.push(m.si); // B259 push si
            m.far(.att_41b6, 0xB25A); // B25A lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B25F or ax, ax
            if (m.sf == m.of) continue :sw 0xB239; // B261 jge 0xb239
            continue :sw 0xB263; // falls through
        },
        0xB263 => {
            m.mark(0xB263);
            m.si = m.di +% 0x0009; // B263 lea si, [di + 9]
            continue :sw 0xB277; // B266 jmp 0xb277
        },
        0xB268 => {
            m.mark(0xB268);
            m.push(0x1B); // B268 push 0x1b
            m.push(m.si); // B26A push si
            m.far(.att_41b6, 0xB26B); // B26B lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B270 or ax, ax
            if (m.sf == m.of) continue :sw 0xB239; // B272 jge 0xb239
            m.si = m.add(u16, m.si, 0x9); // B274 add si, 9
            continue :sw 0xB277; // falls through
        },
        0xB277 => {
            m.mark(0xB277);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B277 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB268; // B27C je 0xb268
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // B27E cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xB291; // B283 jle 0xb291
            m.push(0x1B); // B285 push 0x1b
            m.push(m.si); // B287 push si
            m.far(.att_41b6, 0xB288); // B288 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B28D or ax, ax
            if (m.sf == m.of) continue :sw 0xB239; // B28F jge 0xb239
            continue :sw 0xB291; // falls through
        },
        0xB291 => {
            m.mark(0xB291);
            m.cmp(u8, m.rb(m.bp +% 0xFFF0), 0xB); // B291 cmp byte ptr [bp - 0x10], 0xb
            if (m.zf) continue :sw 0xB2FD; // B295 je 0xb2fd
            m.si = m.di +% 0xFFF5; // B297 lea si, [di - 0xb]
            continue :sw 0xB2AB; // B29A jmp 0xb2ab
        },
        0xB29C => {
            m.mark(0xB29C);
            m.push(0x1B); // B29C push 0x1b
            m.push(m.si); // B29E push si
            m.far(.att_41b6, 0xB29F); // B29F lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B2A4 or ax, ax
            if (m.sf == m.of) continue :sw 0xB239; // B2A6 jge 0xb239
            m.si = m.sub(u16, m.si, 0xB); // B2A8 sub si, 0xb
            continue :sw 0xB2AB; // falls through
        },
        0xB2AB => {
            m.mark(0xB2AB);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B2AB cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB29C; // B2B0 je 0xb29c
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // B2B2 cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xB2C8; // B2B7 jle 0xb2c8
            m.push(0x1B); // B2B9 push 0x1b
            m.push(m.si); // B2BB push si
            m.far(.att_41b6, 0xB2BC); // B2BC lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B2C1 or ax, ax
            if (m.sf != m.of) continue :sw 0xB2C8; // B2C3 jl 0xb2c8
            continue :sw 0xB239; // B2C5 jmp 0xb239
        },
        0xB2C8 => {
            m.mark(0xB2C8);
            m.si = m.di +% 0x000B; // B2C8 lea si, [di + 0xb]
            continue :sw 0xB2E0; // B2CB jmp 0xb2e0
        },
        0xB2CE => {
            m.mark(0xB2CE);
            m.push(0x1B); // B2CE push 0x1b
            m.push(m.si); // B2D0 push si
            m.far(.att_41b6, 0xB2D1); // B2D1 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B2D6 or ax, ax
            if (m.sf != m.of) continue :sw 0xB2DD; // B2D8 jl 0xb2dd
            continue :sw 0xB239; // B2DA jmp 0xb239
        },
        0xB2DD => {
            m.mark(0xB2DD);
            m.si = m.add(u16, m.si, 0xB); // B2DD add si, 0xb
            continue :sw 0xB2E0; // falls through
        },
        0xB2E0 => {
            m.mark(0xB2E0);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B2E0 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB2CE; // B2E5 je 0xb2ce
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // B2E7 cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xB2FD; // B2EC jle 0xb2fd
            m.push(0x1B); // B2EE push 0x1b
            m.push(m.si); // B2F0 push si
            m.far(.att_41b6, 0xB2F1); // B2F1 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B2F6 or ax, ax
            if (m.sf != m.of) continue :sw 0xB2FD; // B2F8 jl 0xb2fd
            continue :sw 0xB239; // B2FA jmp 0xb239
        },
        0xB2FD => {
            m.mark(0xB2FD);
            m.cmp(u8, m.rb(m.bp +% 0xFFF0), 0x1); // B2FD cmp byte ptr [bp - 0x10], 1
            if (m.zf) continue :sw 0xB367; // B301 je 0xb367
            m.si = m.di +% 0x0001; // B303 lea si, [di + 1]
            continue :sw 0xB318; // B306 jmp 0xb318
        },
        0xB308 => {
            m.mark(0xB308);
            m.push(0x1B); // B308 push 0x1b
            m.push(m.si); // B30A push si
            m.far(.att_41b6, 0xB30B); // B30B lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B310 or ax, ax
            if (m.sf != m.of) continue :sw 0xB317; // B312 jl 0xb317
            continue :sw 0xB239; // B314 jmp 0xb239
        },
        0xB317 => {
            m.mark(0xB317);
            m.si = m.inc(u16, m.si); // B317 inc si
            continue :sw 0xB318; // falls through
        },
        0xB318 => {
            m.mark(0xB318);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B318 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB308; // B31D je 0xb308
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // B31F cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xB335; // B324 jle 0xb335
            m.push(0x1B); // B326 push 0x1b
            m.push(m.si); // B328 push si
            m.far(.att_41b6, 0xB329); // B329 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B32E or ax, ax
            if (m.sf != m.of) continue :sw 0xB335; // B330 jl 0xb335
            continue :sw 0xB239; // B332 jmp 0xb239
        },
        0xB335 => {
            m.mark(0xB335);
            m.si = m.di +% 0xFFFF; // B335 lea si, [di - 1]
            continue :sw 0xB34A; // B338 jmp 0xb34a
        },
        0xB33A => {
            m.mark(0xB33A);
            m.push(0x1B); // B33A push 0x1b
            m.push(m.si); // B33C push si
            m.far(.att_41b6, 0xB33D); // B33D lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B342 or ax, ax
            if (m.sf != m.of) continue :sw 0xB349; // B344 jl 0xb349
            continue :sw 0xB239; // B346 jmp 0xb239
        },
        0xB349 => {
            m.mark(0xB349);
            m.si = m.dec(u16, m.si); // B349 dec si
            continue :sw 0xB34A; // falls through
        },
        0xB34A => {
            m.mark(0xB34A);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B34A cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB33A; // B34F je 0xb33a
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // B351 cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xB367; // B356 jle 0xb367
            m.push(0x1B); // B358 push 0x1b
            m.push(m.si); // B35A push si
            m.far(.att_41b6, 0xB35B); // B35B lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B360 or ax, ax
            if (m.sf != m.of) continue :sw 0xB367; // B362 jl 0xb367
            continue :sw 0xB239; // B364 jmp 0xb239
        },
        0xB367 => {
            m.mark(0xB367);
            m.cmp(u8, m.rb(m.bp +% 0xFFF0), 0xA); // B367 cmp byte ptr [bp - 0x10], 0xa
            if (!m.zf) continue :sw 0xB370; // B36B jne 0xb370
            continue :sw 0xB0A7; // B36D jmp 0xb0a7
        },
        0xB370 => {
            m.mark(0xB370);
            m.si = m.di +% 0x000A; // B370 lea si, [di + 0xa]
            continue :sw 0xB388; // B373 jmp 0xb388
        },
        0xB376 => {
            m.mark(0xB376);
            m.push(0x1B); // B376 push 0x1b
            m.push(m.si); // B378 push si
            m.far(.att_41b6, 0xB379); // B379 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B37E or ax, ax
            if (m.sf != m.of) continue :sw 0xB385; // B380 jl 0xb385
            continue :sw 0xB239; // B382 jmp 0xb239
        },
        0xB385 => {
            m.mark(0xB385);
            m.si = m.add(u16, m.si, 0xA); // B385 add si, 0xa
            continue :sw 0xB388; // falls through
        },
        0xB388 => {
            m.mark(0xB388);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B388 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB376; // B38D je 0xb376
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // B38F cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xB3A5; // B394 jle 0xb3a5
            m.push(0x1B); // B396 push 0x1b
            m.push(m.si); // B398 push si
            m.far(.att_41b6, 0xB399); // B399 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B39E or ax, ax
            if (m.sf != m.of) continue :sw 0xB3A5; // B3A0 jl 0xb3a5
            continue :sw 0xB239; // B3A2 jmp 0xb239
        },
        0xB3A5 => {
            m.mark(0xB3A5);
            m.si = m.di +% 0xFFF6; // B3A5 lea si, [di - 0xa]
            continue :sw 0xB3BC; // B3A8 jmp 0xb3bc
        },
        0xB3AA => {
            m.mark(0xB3AA);
            m.push(0x1B); // B3AA push 0x1b
            m.push(m.si); // B3AC push si
            m.far(.att_41b6, 0xB3AD); // B3AD lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B3B2 or ax, ax
            if (m.sf != m.of) continue :sw 0xB3B9; // B3B4 jl 0xb3b9
            continue :sw 0xB239; // B3B6 jmp 0xb239
        },
        0xB3B9 => {
            m.mark(0xB3B9);
            m.si = m.sub(u16, m.si, 0xA); // B3B9 sub si, 0xa
            continue :sw 0xB3BC; // falls through
        },
        0xB3BC => {
            m.mark(0xB3BC);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B3BC cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB3AA; // B3C1 je 0xb3aa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // B3C3 cmp byte ptr [si - 0x610a], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xB3CD; // B3C8 jg 0xb3cd
            continue :sw 0xB0A7; // B3CA jmp 0xb0a7
        },
        0xB3CD => {
            m.mark(0xB3CD);
            m.push(0x1B); // B3CD push 0x1b
            m.push(m.si); // B3CF push si
            m.far(.att_41b6, 0xB3D0); // B3D0 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B3D5 or ax, ax
            if (m.sf != m.of) continue :sw 0xB3DC; // B3D7 jl 0xb3dc
            continue :sw 0xB239; // B3D9 jmp 0xb239
        },
        0xB3DC => {
            m.mark(0xB3DC);
            continue :sw 0xB0A7; // B3DC jmp 0xb0a7
        },
        0xB3E0 => {
            m.mark(0xB3E0);
            m.wb(m.di +% 0x9EF6, 0x5); // B3E0 mov byte ptr [di - 0x610a], 5
            m.bx = m.si; // B3E5 mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // B3E7 sub bx, word ptr [bp - 0xc]
            m.setAl(m.rb(m.bx +% 0x0BB4)); // B3EA mov al, byte ptr [bx + 0xbb4]
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // B3EE or al, byte ptr [bx + 0xab6]
            if (m.zf) continue :sw 0xB415; // B3F2 je 0xb415
            m.push(0x36); // B3F4 push 0x36
            m.push(m.di); // B3F6 push di
            m.far(.att_41b6, 0xB3F7); // B3F7 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B3FC or ax, ax
            if (m.sf == m.of) continue :sw 0xB415; // B3FE jge 0xb415
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // B400 inc word ptr [bp - 8]
            m.ax = m.rw(0xA272); // B403 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // B406 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xB415; // B409 jg 0xb415
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x12C)); // B40B sub word ptr [bp - 2], 0x12c
            m.bx = m.rw(m.bp +% 0x000A); // B410 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // B413 inc byte ptr [bx]
            continue :sw 0xB415; // falls through
        },
        0xB415 => {
            m.mark(0xB415);
            m.setAl(m.rb(0xA03F)); // B415 mov al, byte ptr [0xa03f]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // B418 sub ah, ah
            m.di = m.ax; // B41A mov di, ax
            m.cmp(u16, m.di, 0x62); // B41C cmp di, 0x62
            if (m.zf or m.sf != m.of) continue :sw 0xB424; // B41F jle 0xb424
            continue :sw 0xB893; // B421 jmp 0xb893
        },
        0xB424 => {
            m.mark(0xB424);
            m.cmp(u8, m.rb(m.di +% 0xA09E), m.ah()); // B424 cmp byte ptr [di - 0x5f62], ah
            if (!m.zf and m.sf == m.of) continue :sw 0xB42D; // B428 jg 0xb42d
            continue :sw 0xB5AA; // B42A jmp 0xb5aa
        },
        0xB42D => {
            m.mark(0xB42D);
            m.cmp(u8, m.rb(m.di +% 0xA09E), 0x4); // B42D cmp byte ptr [di - 0x5f62], 4
            if (m.zf or m.sf != m.of) continue :sw 0xB437; // B432 jle 0xb437
            continue :sw 0xB5AA; // B434 jmp 0xb5aa
        },
        0xB437 => {
            m.mark(0xB437);
            m.setAl(m.rb(m.di +% 0xA09E)); // B437 mov al, byte ptr [di - 0x5f62]
            m.cbw(); // B43B cbw
            m.bx = m.ax; // B43C mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // B43E mov al, byte ptr [bx + 0x490]
            m.cbw(); // B442 cbw
            m.si = m.ax; // B443 mov si, ax
            continue :sw 0xB445; // falls through
        },
        0xB445 => {
            m.mark(0xB445);
            m.di = m.add(u16, m.di, m.si); // B445 add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // B447 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xB445; // B44C je 0xb445
            m.si = m.di; // B44E mov si, di
            m.setAl(m.rb(0xA03F)); // B450 mov al, byte ptr [0xa03f]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // B453 sub ah, ah
            m.di = m.ax; // B455 mov di, ax
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xA); // B457 cmp byte ptr [si - 0x610a], 0xa
            if (!m.zf) continue :sw 0xB48E; // B45C jne 0xb48e
            m.ax = m.rw(0x9356); // B45E mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // B461 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xB47C; // B464 jge 0xb47c
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x514)); // B466 sub word ptr [bp - 2], 0x514
            m.bx = m.rw(m.bp +% 0x000A); // B46B mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // B46E inc byte ptr [bx]
            continue :sw 0xB470; // falls through
        },
        0xB470 => {
            m.mark(0xB470);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x12C)); // B470 sub word ptr [bp - 4], 0x12c
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // B475 inc word ptr [bp - 6]
            continue :sw 0xB893; // B478 jmp 0xb893
        },
        0xB47C => {
            m.mark(0xB47C);
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // B47C cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xB470; // B481 je 0xb470
            continue :sw 0xB483; // falls through
        },
        0xB483 => {
            m.mark(0xB483);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x320)); // B483 sub word ptr [bp - 2], 0x320
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // B488 inc word ptr [bp - 8]
            continue :sw 0xCCA6; // B48B jmp 0xcca6
        },
        0xB48E => {
            m.mark(0xB48E);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xC); // B48E cmp byte ptr [si - 0x610a], 0xc
            if (m.zf) continue :sw 0xB498; // B493 je 0xb498
            continue :sw 0xB5AA; // B495 jmp 0xb5aa
        },
        0xB498 => {
            m.mark(0xB498);
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // B498 cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xB4BA; // B49D je 0xb4ba
            continue :sw 0xB49F; // falls through
        },
        0xB49F => {
            m.mark(0xB49F);
            m.ax = m.rw(0x9356); // B49F mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // B4A2 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xB4B1; // B4A5 jge 0xb4b1
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x190)); // B4A7 sub word ptr [bp - 2], 0x190
            m.bx = m.rw(m.bp +% 0x000A); // B4AC mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // B4AF inc byte ptr [bx]
            continue :sw 0xB4B1; // falls through
        },
        0xB4B1 => {
            m.mark(0xB4B1);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x320)); // B4B1 sub word ptr [bp - 2], 0x320
            continue :sw 0xCCA6; // B4B6 jmp 0xcca6
        },
        0xB4BA => {
            m.mark(0xB4BA);
            m.si = m.di +% 0x00B0; // B4BA lea si, [di + 0xb0]
            m.bx = m.si; // B4BE mov bx, si
            m.setAl(m.rb(0xA04A)); // B4C0 mov al, byte ptr [0xa04a]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // B4C3 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // B4C5 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x09B8)); // B4C7 mov al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // B4CB mov bx, si
            m.setCl(m.rb(0xA04B)); // B4CD mov cl, byte ptr [0xa04b]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // B4D1 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // B4D3 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // B4D5 or al, byte ptr [bx + 0x9b8]
            if (m.zf) continue :sw 0xB4F8; // B4D9 je 0xb4f8
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x15E)); // B4DB sub word ptr [bp - 4], 0x15e
            m.ax = m.rw(0x9356); // B4E0 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // B4E3 cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xB4EB; // B4E6 jl 0xb4eb
            continue :sw 0xB893; // B4E8 jmp 0xb893
        },
        0xB4EB => {
            m.mark(0xB4EB);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x320)); // B4EB sub word ptr [bp - 2], 0x320
            continue :sw 0xB4F0; // falls through
        },
        0xB4F0 => {
            m.mark(0xB4F0);
            m.bx = m.rw(m.bp +% 0x000A); // B4F0 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // B4F3 inc byte ptr [bx]
            continue :sw 0xB893; // B4F5 jmp 0xb893
        },
        0xB4F8 => {
            m.mark(0xB4F8);
            m.cmp(u8, m.rb(m.di +% 0xA09E), 0x1); // B4F8 cmp byte ptr [di - 0x5f62], 1
            if (m.zf) continue :sw 0xB506; // B4FD je 0xb506
            m.cmp(u8, m.rb(m.di +% 0xA09E), 0x3); // B4FF cmp byte ptr [di - 0x5f62], 3
            if (!m.zf) continue :sw 0xB55A; // B504 jne 0xb55a
            continue :sw 0xB506; // falls through
        },
        0xB506 => {
            m.mark(0xB506);
            m.si = m.di +% 0x000B; // B506 lea si, [di + 0xb]
            continue :sw 0xB50F; // B509 jmp 0xb50f
        },
        0xB50C => {
            m.mark(0xB50C);
            m.si = m.add(u16, m.si, 0xB); // B50C add si, 0xb
            continue :sw 0xB50F; // falls through
        },
        0xB50F => {
            m.mark(0xB50F);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B50F cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB50C; // B514 je 0xb50c
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xA); // B516 cmp byte ptr [si - 0x610a], 0xa
            if (!m.zf) continue :sw 0xB53C; // B51B jne 0xb53c
            m.ax = m.si; // B51D mov ax, si
            m.ax = m.sub(u16, m.ax, m.di); // B51F sub ax, di
            continue :sw 0xB521; // falls through
        },
        0xB521 => {
            m.mark(0xB521);
            m.cmp(u16, m.ax, 0xB); // B521 cmp ax, 0xb
            continue :sw 0xB524; // falls through
        },
        0xB524 => {
            m.mark(0xB524);
            if (!m.zf) continue :sw 0xB52B; // B524 jne 0xb52b
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x12C)); // B526 sub word ptr [bp - 4], 0x12c
            continue :sw 0xB52B; // falls through
        },
        0xB52B => {
            m.mark(0xB52B);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0xC8)); // B52B sub word ptr [bp - 4], 0xc8
            m.ax = m.rw(0x9356); // B530 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // B533 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xB5B5; // B536 jge 0xb5b5
            continue :sw 0xB730; // B538 jmp 0xb730
        },
        0xB53C => {
            m.mark(0xB53C);
            m.si = m.di +% 0xFFF5; // B53C lea si, [di - 0xb]
            continue :sw 0xB545; // B53F jmp 0xb545
        },
        0xB542 => {
            m.mark(0xB542);
            m.si = m.sub(u16, m.si, 0xB); // B542 sub si, 0xb
            continue :sw 0xB545; // falls through
        },
        0xB545 => {
            m.mark(0xB545);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B545 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB542; // B54A je 0xb542
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xA); // B54C cmp byte ptr [si - 0x610a], 0xa
            if (!m.zf) continue :sw 0xB598; // B551 jne 0xb598
            m.ax = m.di; // B553 mov ax, di
            m.ax = m.sub(u16, m.ax, m.si); // B555 sub ax, si
            continue :sw 0xB521; // B557 jmp 0xb521
        },
        0xB55A => {
            m.mark(0xB55A);
            m.si = m.di +% 0x0009; // B55A lea si, [di + 9]
            continue :sw 0xB563; // B55D jmp 0xb563
        },
        0xB560 => {
            m.mark(0xB560);
            m.si = m.add(u16, m.si, 0x9); // B560 add si, 9
            continue :sw 0xB563; // falls through
        },
        0xB563 => {
            m.mark(0xB563);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B563 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB560; // B568 je 0xb560
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xA); // B56A cmp byte ptr [si - 0x610a], 0xa
            if (!m.zf) continue :sw 0xB578; // B56F jne 0xb578
            m.ax = m.si; // B571 mov ax, si
            m.ax = m.sub(u16, m.ax, m.di); // B573 sub ax, di
            continue :sw 0xB593; // B575 jmp 0xb593
        },
        0xB578 => {
            m.mark(0xB578);
            m.si = m.di +% 0xFFF7; // B578 lea si, [di - 9]
            continue :sw 0xB581; // B57B jmp 0xb581
        },
        0xB57E => {
            m.mark(0xB57E);
            m.si = m.sub(u16, m.si, 0x9); // B57E sub si, 9
            continue :sw 0xB581; // falls through
        },
        0xB581 => {
            m.mark(0xB581);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B581 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB57E; // B586 je 0xb57e
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xA); // B588 cmp byte ptr [si - 0x610a], 0xa
            if (!m.zf) continue :sw 0xB598; // B58D jne 0xb598
            m.ax = m.di; // B58F mov ax, di
            m.ax = m.sub(u16, m.ax, m.si); // B591 sub ax, si
            continue :sw 0xB593; // falls through
        },
        0xB593 => {
            m.mark(0xB593);
            m.cmp(u16, m.ax, 0x9); // B593 cmp ax, 9
            continue :sw 0xB524; // B596 jmp 0xb524
        },
        0xB598 => {
            m.mark(0xB598);
            m.push(0x1E); // B598 push 0x1e
            m.push(m.di); // B59A push di
            m.far(.att_41b6, 0xB59B); // B59B lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B5A0 or ax, ax
            if (m.sf != m.of) continue :sw 0xB5A7; // B5A2 jl 0xb5a7
            continue :sw 0xB893; // B5A4 jmp 0xb893
        },
        0xB5A7 => {
            m.mark(0xB5A7);
            continue :sw 0xB52B; // B5A7 jmp 0xb52b
        },
        0xB5AA => {
            m.mark(0xB5AA);
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // B5AA cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xB5F0; // B5AF je 0xb5f0
            m.ww(m.bp +% 0xFFFA, m.add(u16, m.rw(m.bp +% 0xFFFA), 0xD)); // B5B1 add word ptr [bp - 6], 0xd
            continue :sw 0xB5B5; // falls through
        },
        0xB5B5 => {
            m.mark(0xB5B5);
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // B5B5 inc word ptr [bp - 6]
            continue :sw 0xB5B8; // falls through
        },
        0xB5B8 => {
            m.mark(0xB5B8);
            m.cmp(u16, m.di, 0x1C); // B5B8 cmp di, 0x1c
            if (m.zf or m.sf != m.of) continue :sw 0xB5C0; // B5BB jle 0xb5c0
            continue :sw 0xB799; // B5BD jmp 0xb799
        },
        0xB5C0 => {
            m.mark(0xB5C0);
            m.cmp(u8, m.rb(m.di +% 0x9F00), 0x0); // B5C0 cmp byte ptr [di - 0x6100], 0
            if (!m.zf) continue :sw 0xB5CA; // B5C5 jne 0xb5ca
            continue :sw 0xB799; // B5C7 jmp 0xb799
        },
        0xB5CA => {
            m.mark(0xB5CA);
            m.cmp(u8, m.rb(m.di +% 0x9F00), 0x8); // B5CA cmp byte ptr [di - 0x6100], 8
            if (m.zf) continue :sw 0xB5D4; // B5CF je 0xb5d4
            continue :sw 0xB780; // B5D1 jmp 0xb780
        },
        0xB5D4 => {
            m.mark(0xB5D4);
            m.ax = m.rw(0x9356); // B5D4 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // B5D7 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xB5DF; // B5DA jge 0xb5df
            continue :sw 0xB730; // B5DC jmp 0xb730
        },
        0xB5DF => {
            m.mark(0xB5DF);
            m.cmp(u16, m.rw(m.bp +% 0xFFFA), 0x0); // B5DF cmp word ptr [bp - 6], 0
            if (!m.zf) continue :sw 0xB5E8; // B5E3 jne 0xb5e8
            continue :sw 0xB799; // B5E5 jmp 0xb799
        },
        0xB5E8 => {
            m.mark(0xB5E8);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0xC8)); // B5E8 sub word ptr [bp - 4], 0xc8
            continue :sw 0xB799; // B5ED jmp 0xb799
        },
        0xB5F0 => {
            m.mark(0xB5F0);
            m.si = m.di +% 0x00B0; // B5F0 lea si, [di + 0xb0]
            m.bx = m.si; // B5F4 mov bx, si
            m.setAl(m.rb(0xA04A)); // B5F6 mov al, byte ptr [0xa04a]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // B5F9 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // B5FB sub bx, ax
            m.setAl(m.rb(m.bx +% 0x09B8)); // B5FD mov al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // B601 mov bx, si
            m.setCl(m.rb(0xA04B)); // B603 mov cl, byte ptr [0xa04b]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // B607 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // B609 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // B60B or al, byte ptr [bx + 0x9b8]
            if (!m.zf) continue :sw 0xB5B5; // B60F jne 0xb5b5
            m.cmp(u8, m.rb(m.di +% 0x0E16), m.ah()); // B611 cmp byte ptr [di + 0xe16], ah
            if (m.zf) continue :sw 0xB630; // B615 je 0xb630
            m.bx = m.si; // B617 mov bx, si
            m.setAl(m.rb(0xA04C)); // B619 mov al, byte ptr [0xa04c]
            m.bx = m.sub(u16, m.bx, m.ax); // B61C sub bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), m.ah()); // B61E cmp byte ptr [bx + 0xab6], ah
            if (!m.zf) continue :sw 0xB627; // B622 jne 0xb627
            continue :sw 0xB6CA; // B624 jmp 0xb6ca
        },
        0xB627 => {
            m.mark(0xB627);
            m.cmp(u8, m.al(), 0x63); // B627 cmp al, 0x63
            if (m.cf) continue :sw 0xB62E; // B629 jb 0xb62e
            continue :sw 0xB6CA; // B62B jmp 0xb6ca
        },
        0xB62E => {
            m.mark(0xB62E);
            continue :sw 0xB646; // B62E jmp 0xb646
        },
        0xB630 => {
            m.mark(0xB630);
            m.bx = m.si; // B630 mov bx, si
            m.setAl(m.rb(0xA04D)); // B632 mov al, byte ptr [0xa04d]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // B635 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // B637 sub bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), m.ah()); // B639 cmp byte ptr [bx + 0xab6], ah
            if (!m.zf) continue :sw 0xB642; // B63D jne 0xb642
            continue :sw 0xB6CA; // B63F jmp 0xb6ca
        },
        0xB642 => {
            m.mark(0xB642);
            m.bx = m.si; // B642 mov bx, si
            m.bx = m.sub(u16, m.bx, m.ax); // B644 sub bx, ax
            continue :sw 0xB646; // falls through
        },
        0xB646 => {
            m.mark(0xB646);
            m.setAl(m.rb(m.bx +% 0x0AB6)); // B646 mov al, byte ptr [bx + 0xab6]
            m.cbw(); // B64A cbw
            m.ww(m.bp +% 0xFFF6, m.ax); // B64B mov word ptr [bp - 0xa], ax
            m.si = m.ax; // B64E mov si, ax
            m.si = m.add(u16, m.si, m.di); // B650 add si, di
            continue :sw 0xB659; // B652 jmp 0xb659
        },
        0xB656 => {
            m.mark(0xB656);
            m.si = m.add(u16, m.si, m.rw(m.bp +% 0xFFF6)); // B656 add si, word ptr [bp - 0xa]
            continue :sw 0xB659; // falls through
        },
        0xB659 => {
            m.mark(0xB659);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B659 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB656; // B65E je 0xb656
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xA); // B660 cmp byte ptr [si - 0x610a], 0xa
            if (!m.zf) continue :sw 0xB6C6; // B665 jne 0xb6c6
            m.ax = m.si; // B667 mov ax, si
            m.ax = m.sub(u16, m.ax, m.rw(m.bp +% 0xFFF6)); // B669 sub ax, word ptr [bp - 0xa]
            m.cmp(u16, m.ax, m.di); // B66C cmp ax, di
            if (!m.zf) continue :sw 0xB692; // B66E jne 0xb692
            m.si = m.di; // B670 mov si, di
            continue :sw 0xB672; // falls through
        },
        0xB672 => {
            m.mark(0xB672);
            m.si = m.sub(u16, m.si, m.rw(m.bp +% 0xFFF6)); // B672 sub si, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B675 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB672; // B67A je 0xb672
            m.setAl(m.rb(m.si +% 0x9EF6)); // B67C mov al, byte ptr [si - 0x610a]
            m.cbw(); // B680 cbw
            m.bx = m.ax; // B681 mov bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x1270), 0x0); // B683 cmp byte ptr [bx + 0x1270], 0
            if (m.zf) continue :sw 0xB6AF; // B688 je 0xb6af
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0xC8)); // B68A sub word ptr [bp - 4], 0xc8
            continue :sw 0xB52B; // B68F jmp 0xb52b
        },
        0xB692 => {
            m.mark(0xB692);
            m.si = m.di; // B692 mov si, di
            continue :sw 0xB694; // falls through
        },
        0xB694 => {
            m.mark(0xB694);
            m.si = m.sub(u16, m.si, m.rw(m.bp +% 0xFFF6)); // B694 sub si, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B697 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB694; // B69C je 0xb694
            m.setAl(m.rb(m.si +% 0x9EF6)); // B69E mov al, byte ptr [si - 0x610a]
            m.cbw(); // B6A2 cbw
            m.bx = m.ax; // B6A3 mov bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x1270), 0x0); // B6A5 cmp byte ptr [bx + 0x1270], 0
            if (m.zf) continue :sw 0xB6AF; // B6AA je 0xb6af
            continue :sw 0xB52B; // B6AC jmp 0xb52b
        },
        0xB6AF => {
            m.mark(0xB6AF);
            m.ax = m.rw(0xA272); // B6AF mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // B6B2 cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xB6BA; // B6B5 jle 0xb6ba
            continue :sw 0xB5B5; // B6B7 jmp 0xb5b5
        },
        0xB6BA => {
            m.mark(0xB6BA);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x64)); // B6BA sub word ptr [bp - 2], 0x64
            m.bx = m.rw(m.bp +% 0x000A); // B6BE mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // B6C1 inc byte ptr [bx]
            continue :sw 0xB5B5; // B6C3 jmp 0xb5b5
        },
        0xB6C6 => {
            m.mark(0xB6C6);
            m.si = m.di +% 0x00B0; // B6C6 lea si, [di + 0xb0]
            continue :sw 0xB6CA; // falls through
        },
        0xB6CA => {
            m.mark(0xB6CA);
            m.bx = m.si; // B6CA mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // B6CC sub bx, word ptr [bp - 0xc]
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), 0x0); // B6CF cmp byte ptr [bx + 0xab6], 0
            if (m.zf) continue :sw 0xB70E; // B6D4 je 0xb70e
            m.setAl(m.rb(m.bx +% 0x0AB6)); // B6D6 mov al, byte ptr [bx + 0xab6]
            m.cbw(); // B6DA cbw
            m.ww(m.bp +% 0xFFF6, m.ax); // B6DB mov word ptr [bp - 0xa], ax
            m.ax = m.add(u16, m.ax, m.di); // B6DE add ax, di
            m.si = m.ax; // B6E0 mov si, ax
            continue :sw 0xB6E7; // B6E2 jmp 0xb6e7
        },
        0xB6E4 => {
            m.mark(0xB6E4);
            m.si = m.add(u16, m.si, m.rw(m.bp +% 0xFFF6)); // B6E4 add si, word ptr [bp - 0xa]
            continue :sw 0xB6E7; // falls through
        },
        0xB6E7 => {
            m.mark(0xB6E7);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B6E7 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB6E4; // B6EC je 0xb6e4
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xC); // B6EE cmp byte ptr [si - 0x610a], 0xc
            if (!m.zf) continue :sw 0xB70A; // B6F3 jne 0xb70a
            m.push(0x1E); // B6F5 push 0x1e
            m.push(m.di); // B6F7 push di
            m.far(.att_41b6, 0xB6F8); // B6F8 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B6FD or ax, ax
            if (m.sf != m.of) continue :sw 0xB704; // B6FF jl 0xb704
            continue :sw 0xB893; // B701 jmp 0xb893
        },
        0xB704 => {
            m.mark(0xB704);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // B704 inc word ptr [bp - 8]
            continue :sw 0xB5B8; // B707 jmp 0xb5b8
        },
        0xB70A => {
            m.mark(0xB70A);
            m.si = m.di +% 0x00B0; // B70A lea si, [di + 0xb0]
            continue :sw 0xB70E; // falls through
        },
        0xB70E => {
            m.mark(0xB70E);
            m.bx = m.di; // B70E mov bx, di
            m.setAl(m.rb(0xA051)); // B710 mov al, byte ptr [0xa051]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // B713 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // B715 sub bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x0CFF), m.ah()); // B717 cmp byte ptr [bx + 0xcff], ah
            if (m.zf) continue :sw 0xB738; // B71B je 0xb738
            m.push(0x1E); // B71D push 0x1e
            m.push(m.di); // B71F push di
            m.far(.att_41b6, 0xB720); // B720 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B725 or ax, ax
            if (m.sf == m.of) continue :sw 0xB738; // B727 jge 0xb738
            m.cmp(u8, m.rb(0xA5F5), 0x0); // B729 cmp byte ptr [0xa5f5], 0
            if (m.zf) continue :sw 0xB704; // B72E je 0xb704
            continue :sw 0xB730; // falls through
        },
        0xB730 => {
            m.mark(0xB730);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x2BC)); // B730 sub word ptr [bp - 2], 0x2bc
            continue :sw 0xB4F0; // B735 jmp 0xb4f0
        },
        0xB738 => {
            m.mark(0xB738);
            m.bx = m.si; // B738 mov bx, si
            m.setAl(m.rb(0xA04E)); // B73A mov al, byte ptr [0xa04e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // B73D sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // B73F sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0BB4)); // B741 mov al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // B745 mov bx, si
            m.setCl(m.rb(0xA04F)); // B747 mov cl, byte ptr [0xa04f]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // B74B sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // B74D sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // B74F or al, byte ptr [bx + 0xbb4]
            m.@"test"(u8, m.al(), 0x1); // B753 test al, 1
            if (!m.zf) continue :sw 0xB75A; // B755 jne 0xb75a
            continue :sw 0xB893; // B757 jmp 0xb893
        },
        0xB75A => {
            m.mark(0xB75A);
            m.push(0x1E); // B75A push 0x1e
            m.push(m.di); // B75C push di
            m.far(.att_41b6, 0xB75D); // B75D lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B762 or ax, ax
            if (m.sf != m.of) continue :sw 0xB769; // B764 jl 0xb769
            continue :sw 0xB893; // B766 jmp 0xb893
        },
        0xB769 => {
            m.mark(0xB769);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // B769 inc word ptr [bp - 8]
            m.ax = m.rw(0xA272); // B76C mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // B76F cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xB777; // B772 jle 0xb777
            continue :sw 0xB893; // B774 jmp 0xb893
        },
        0xB777 => {
            m.mark(0xB777);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xFA)); // B777 sub word ptr [bp - 2], 0xfa
            continue :sw 0xB4F0; // B77C jmp 0xb4f0
        },
        0xB780 => {
            m.mark(0xB780);
            m.cmp(u8, m.rb(m.di +% 0x9F00), 0x7); // B780 cmp byte ptr [di - 0x6100], 7
            if (m.sf == m.of) continue :sw 0xB799; // B785 jge 0xb799
            m.ax = m.rw(0xA272); // B787 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // B78A cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xB799; // B78D jg 0xb799
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x12C)); // B78F sub word ptr [bp - 2], 0x12c
            m.bx = m.rw(m.bp +% 0x000A); // B794 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // B797 inc byte ptr [bx]
            continue :sw 0xB799; // falls through
        },
        0xB799 => {
            m.mark(0xB799);
            m.wb(m.di +% 0x9EF6, 0x0); // B799 mov byte ptr [di - 0x610a], 0
            m.si = m.di +% 0xFFF6; // B79E lea si, [di - 0xa]
            continue :sw 0xB7B6; // B7A1 jmp 0xb7b6
        },
        0xB7A4 => {
            m.mark(0xB7A4);
            m.push(0xF); // B7A4 push 0xf
            m.push(m.si); // B7A6 push si
            m.far(.att_41b6, 0xB7A7); // B7A7 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B7AC or ax, ax
            if (m.sf != m.of) continue :sw 0xB7B3; // B7AE jl 0xb7b3
            continue :sw 0xB88E; // B7B0 jmp 0xb88e
        },
        0xB7B3 => {
            m.mark(0xB7B3);
            m.si = m.sub(u16, m.si, 0xA); // B7B3 sub si, 0xa
            continue :sw 0xB7B6; // falls through
        },
        0xB7B6 => {
            m.mark(0xB7B6);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B7B6 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB7A4; // B7BB je 0xb7a4
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // B7BD cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xB7D3; // B7C2 jle 0xb7d3
            m.push(0xF); // B7C4 push 0xf
            m.push(m.si); // B7C6 push si
            m.far(.att_41b6, 0xB7C7); // B7C7 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B7CC or ax, ax
            if (m.sf != m.of) continue :sw 0xB7D3; // B7CE jl 0xb7d3
            continue :sw 0xB88E; // B7D0 jmp 0xb88e
        },
        0xB7D3 => {
            m.mark(0xB7D3);
            m.si = m.di +% 0xFFFF; // B7D3 lea si, [di - 1]
            continue :sw 0xB7E8; // B7D6 jmp 0xb7e8
        },
        0xB7D8 => {
            m.mark(0xB7D8);
            m.push(0xF); // B7D8 push 0xf
            m.push(m.si); // B7DA push si
            m.far(.att_41b6, 0xB7DB); // B7DB lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B7E0 or ax, ax
            if (m.sf != m.of) continue :sw 0xB7E7; // B7E2 jl 0xb7e7
            continue :sw 0xB88E; // B7E4 jmp 0xb88e
        },
        0xB7E7 => {
            m.mark(0xB7E7);
            m.si = m.dec(u16, m.si); // B7E7 dec si
            continue :sw 0xB7E8; // falls through
        },
        0xB7E8 => {
            m.mark(0xB7E8);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B7E8 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB7D8; // B7ED je 0xb7d8
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // B7EF cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xB805; // B7F4 jle 0xb805
            m.push(0xF); // B7F6 push 0xf
            m.push(m.si); // B7F8 push si
            m.far(.att_41b6, 0xB7F9); // B7F9 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B7FE or ax, ax
            if (m.sf != m.of) continue :sw 0xB805; // B800 jl 0xb805
            continue :sw 0xB88E; // B802 jmp 0xb88e
        },
        0xB805 => {
            m.mark(0xB805);
            m.si = m.di +% 0x0001; // B805 lea si, [di + 1]
            continue :sw 0xB819; // B808 jmp 0xb819
        },
        0xB80C => {
            m.mark(0xB80C);
            m.push(0xF); // B80C push 0xf
            m.push(m.si); // B80E push si
            m.far(.att_41b6, 0xB80F); // B80F lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B814 or ax, ax
            if (m.sf == m.of) continue :sw 0xB88E; // B816 jge 0xb88e
            m.si = m.inc(u16, m.si); // B818 inc si
            continue :sw 0xB819; // falls through
        },
        0xB819 => {
            m.mark(0xB819);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B819 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB80C; // B81E je 0xb80c
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // B820 cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xB833; // B825 jle 0xb833
            m.push(0xF); // B827 push 0xf
            m.push(m.si); // B829 push si
            m.far(.att_41b6, 0xB82A); // B82A lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B82F or ax, ax
            if (m.sf == m.of) continue :sw 0xB88E; // B831 jge 0xb88e
            continue :sw 0xB833; // falls through
        },
        0xB833 => {
            m.mark(0xB833);
            m.si = m.di +% 0x000A; // B833 lea si, [di + 0xa]
            continue :sw 0xB847; // B836 jmp 0xb847
        },
        0xB838 => {
            m.mark(0xB838);
            m.push(0xF); // B838 push 0xf
            m.push(m.si); // B83A push si
            m.far(.att_41b6, 0xB83B); // B83B lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B840 or ax, ax
            if (m.sf == m.of) continue :sw 0xB88E; // B842 jge 0xb88e
            m.si = m.add(u16, m.si, 0xA); // B844 add si, 0xa
            continue :sw 0xB847; // falls through
        },
        0xB847 => {
            m.mark(0xB847);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B847 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB838; // B84C je 0xb838
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // B84E cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xB861; // B853 jle 0xb861
            m.push(0xF); // B855 push 0xf
            m.push(m.si); // B857 push si
            m.far(.att_41b6, 0xB858); // B858 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // B85D or ax, ax
            if (m.sf == m.of) continue :sw 0xB88E; // B85F jge 0xb88e
            continue :sw 0xB861; // falls through
        },
        0xB861 => {
            m.mark(0xB861);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x12C)); // B861 sub word ptr [bp - 4], 0x12c
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // B866 cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xB87C; // B86B je 0xb87c
            m.ax = m.rw(0xA5EC); // B86D mov ax, word ptr [0xa5ec]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // B870 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xB88E; // B873 jge 0xb88e
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x384)); // B875 sub word ptr [bp - 2], 0x384
            continue :sw 0xB889; // B87A jmp 0xb889
        },
        0xB87C => {
            m.mark(0xB87C);
            m.ax = m.rw(0x9356); // B87C mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // B87F cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xB88E; // B882 jge 0xb88e
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x2BC)); // B884 sub word ptr [bp - 2], 0x2bc
            continue :sw 0xB889; // falls through
        },
        0xB889 => {
            m.mark(0xB889);
            m.bx = m.rw(m.bp +% 0x000A); // B889 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // B88C inc byte ptr [bx]
            continue :sw 0xB88E; // falls through
        },
        0xB88E => {
            m.mark(0xB88E);
            m.wb(m.di +% 0x9EF6, 0x4); // B88E mov byte ptr [di - 0x610a], 4
            continue :sw 0xB893; // falls through
        },
        0xB893 => {
            m.mark(0xB893);
            m.setAl(m.rb(0xA03E)); // B893 mov al, byte ptr [0xa03e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // B896 sub ah, ah
            m.di = m.ax; // B898 mov di, ax
            m.cmp(u16, m.di, 0x62); // B89A cmp di, 0x62
            if (m.zf or m.sf != m.of) continue :sw 0xB8A2; // B89D jle 0xb8a2
            continue :sw 0xBCF3; // B89F jmp 0xbcf3
        },
        0xB8A2 => {
            m.mark(0xB8A2);
            m.cmp(u8, m.rb(m.di +% 0xA09E), m.ah()); // B8A2 cmp byte ptr [di - 0x5f62], ah
            if (!m.zf and m.sf == m.of) continue :sw 0xB8AB; // B8A6 jg 0xb8ab
            continue :sw 0xBA0A; // B8A8 jmp 0xba0a
        },
        0xB8AB => {
            m.mark(0xB8AB);
            m.cmp(u8, m.rb(m.di +% 0xA09E), 0x4); // B8AB cmp byte ptr [di - 0x5f62], 4
            if (m.zf or m.sf != m.of) continue :sw 0xB8B5; // B8B0 jle 0xb8b5
            continue :sw 0xBA0A; // B8B2 jmp 0xba0a
        },
        0xB8B5 => {
            m.mark(0xB8B5);
            m.setAl(m.rb(m.di +% 0xA09E)); // B8B5 mov al, byte ptr [di - 0x5f62]
            m.cbw(); // B8B9 cbw
            m.bx = m.ax; // B8BA mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // B8BC mov al, byte ptr [bx + 0x490]
            m.cbw(); // B8C0 cbw
            m.si = m.ax; // B8C1 mov si, ax
            continue :sw 0xB8C3; // falls through
        },
        0xB8C3 => {
            m.mark(0xB8C3);
            m.di = m.add(u16, m.di, m.si); // B8C3 add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // B8C5 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xB8C3; // B8CA je 0xb8c3
            m.si = m.di; // B8CC mov si, di
            m.setAl(m.rb(0xA03E)); // B8CE mov al, byte ptr [0xa03e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // B8D1 sub ah, ah
            m.di = m.ax; // B8D3 mov di, ax
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xA); // B8D5 cmp byte ptr [si - 0x610a], 0xa
            if (!m.zf) continue :sw 0xB906; // B8DA jne 0xb906
            m.ax = m.rw(0x9356); // B8DC mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // B8DF cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xB8F0; // B8E2 jge 0xb8f0
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x514)); // B8E4 sub word ptr [bp - 2], 0x514
            m.bx = m.rw(m.bp +% 0x000A); // B8E9 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // B8EC inc byte ptr [bx]
            continue :sw 0xB8FA; // B8EE jmp 0xb8fa
        },
        0xB8F0 => {
            m.mark(0xB8F0);
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // B8F0 cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xB8FA; // B8F5 je 0xb8fa
            continue :sw 0xB483; // B8F7 jmp 0xb483
        },
        0xB8FA => {
            m.mark(0xB8FA);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x12C)); // B8FA sub word ptr [bp - 4], 0x12c
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // B8FF inc word ptr [bp - 6]
            continue :sw 0xBCF3; // B902 jmp 0xbcf3
        },
        0xB906 => {
            m.mark(0xB906);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xC); // B906 cmp byte ptr [si - 0x610a], 0xc
            if (m.zf) continue :sw 0xB910; // B90B je 0xb910
            continue :sw 0xBA0A; // B90D jmp 0xba0a
        },
        0xB910 => {
            m.mark(0xB910);
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // B910 cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xB91A; // B915 je 0xb91a
            continue :sw 0xB49F; // B917 jmp 0xb49f
        },
        0xB91A => {
            m.mark(0xB91A);
            m.si = m.di +% 0x00B0; // B91A lea si, [di + 0xb0]
            m.bx = m.si; // B91E mov bx, si
            m.setAl(m.rb(0xA04A)); // B920 mov al, byte ptr [0xa04a]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // B923 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // B925 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x09B8)); // B927 mov al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // B92B mov bx, si
            m.setCl(m.rb(0xA04B)); // B92D mov cl, byte ptr [0xa04b]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // B931 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // B933 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // B935 or al, byte ptr [bx + 0x9b8]
            if (m.zf) continue :sw 0xB958; // B939 je 0xb958
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x15E)); // B93B sub word ptr [bp - 4], 0x15e
            m.ax = m.rw(0x9356); // B940 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // B943 cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xB94B; // B946 jl 0xb94b
            continue :sw 0xBCF3; // B948 jmp 0xbcf3
        },
        0xB94B => {
            m.mark(0xB94B);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x320)); // B94B sub word ptr [bp - 2], 0x320
            continue :sw 0xB950; // falls through
        },
        0xB950 => {
            m.mark(0xB950);
            m.bx = m.rw(m.bp +% 0x000A); // B950 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // B953 inc byte ptr [bx]
            continue :sw 0xBCF3; // B955 jmp 0xbcf3
        },
        0xB958 => {
            m.mark(0xB958);
            m.cmp(u8, m.rb(m.di +% 0xA09E), 0x1); // B958 cmp byte ptr [di - 0x5f62], 1
            if (m.zf) continue :sw 0xB966; // B95D je 0xb966
            m.cmp(u8, m.rb(m.di +% 0xA09E), 0x3); // B95F cmp byte ptr [di - 0x5f62], 3
            if (!m.zf) continue :sw 0xB9BA; // B964 jne 0xb9ba
            continue :sw 0xB966; // falls through
        },
        0xB966 => {
            m.mark(0xB966);
            m.si = m.di +% 0x000B; // B966 lea si, [di + 0xb]
            continue :sw 0xB96F; // B969 jmp 0xb96f
        },
        0xB96C => {
            m.mark(0xB96C);
            m.si = m.add(u16, m.si, 0xB); // B96C add si, 0xb
            continue :sw 0xB96F; // falls through
        },
        0xB96F => {
            m.mark(0xB96F);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B96F cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB96C; // B974 je 0xb96c
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xA); // B976 cmp byte ptr [si - 0x610a], 0xa
            if (!m.zf) continue :sw 0xB99C; // B97B jne 0xb99c
            m.ax = m.si; // B97D mov ax, si
            m.ax = m.sub(u16, m.ax, m.di); // B97F sub ax, di
            continue :sw 0xB981; // falls through
        },
        0xB981 => {
            m.mark(0xB981);
            m.cmp(u16, m.ax, 0xB); // B981 cmp ax, 0xb
            continue :sw 0xB984; // falls through
        },
        0xB984 => {
            m.mark(0xB984);
            if (!m.zf) continue :sw 0xB98B; // B984 jne 0xb98b
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x12C)); // B986 sub word ptr [bp - 4], 0x12c
            continue :sw 0xB98B; // falls through
        },
        0xB98B => {
            m.mark(0xB98B);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0xC8)); // B98B sub word ptr [bp - 4], 0xc8
            m.ax = m.rw(0x9356); // B990 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // B993 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xBA15; // B996 jge 0xba15
            continue :sw 0xBB90; // B998 jmp 0xbb90
        },
        0xB99C => {
            m.mark(0xB99C);
            m.si = m.di +% 0xFFF5; // B99C lea si, [di - 0xb]
            continue :sw 0xB9A5; // B99F jmp 0xb9a5
        },
        0xB9A2 => {
            m.mark(0xB9A2);
            m.si = m.sub(u16, m.si, 0xB); // B9A2 sub si, 0xb
            continue :sw 0xB9A5; // falls through
        },
        0xB9A5 => {
            m.mark(0xB9A5);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B9A5 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB9A2; // B9AA je 0xb9a2
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xA); // B9AC cmp byte ptr [si - 0x610a], 0xa
            if (!m.zf) continue :sw 0xB9F8; // B9B1 jne 0xb9f8
            m.ax = m.di; // B9B3 mov ax, di
            m.ax = m.sub(u16, m.ax, m.si); // B9B5 sub ax, si
            continue :sw 0xB981; // B9B7 jmp 0xb981
        },
        0xB9BA => {
            m.mark(0xB9BA);
            m.si = m.di +% 0x0009; // B9BA lea si, [di + 9]
            continue :sw 0xB9C3; // B9BD jmp 0xb9c3
        },
        0xB9C0 => {
            m.mark(0xB9C0);
            m.si = m.add(u16, m.si, 0x9); // B9C0 add si, 9
            continue :sw 0xB9C3; // falls through
        },
        0xB9C3 => {
            m.mark(0xB9C3);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B9C3 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB9C0; // B9C8 je 0xb9c0
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xA); // B9CA cmp byte ptr [si - 0x610a], 0xa
            if (!m.zf) continue :sw 0xB9D8; // B9CF jne 0xb9d8
            m.ax = m.si; // B9D1 mov ax, si
            m.ax = m.sub(u16, m.ax, m.di); // B9D3 sub ax, di
            continue :sw 0xB9F3; // B9D5 jmp 0xb9f3
        },
        0xB9D8 => {
            m.mark(0xB9D8);
            m.si = m.di +% 0xFFF7; // B9D8 lea si, [di - 9]
            continue :sw 0xB9E1; // B9DB jmp 0xb9e1
        },
        0xB9DE => {
            m.mark(0xB9DE);
            m.si = m.sub(u16, m.si, 0x9); // B9DE sub si, 9
            continue :sw 0xB9E1; // falls through
        },
        0xB9E1 => {
            m.mark(0xB9E1);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // B9E1 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xB9DE; // B9E6 je 0xb9de
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xA); // B9E8 cmp byte ptr [si - 0x610a], 0xa
            if (!m.zf) continue :sw 0xB9F8; // B9ED jne 0xb9f8
            m.ax = m.di; // B9EF mov ax, di
            m.ax = m.sub(u16, m.ax, m.si); // B9F1 sub ax, si
            continue :sw 0xB9F3; // falls through
        },
        0xB9F3 => {
            m.mark(0xB9F3);
            m.cmp(u16, m.ax, 0x9); // B9F3 cmp ax, 9
            continue :sw 0xB984; // B9F6 jmp 0xb984
        },
        0xB9F8 => {
            m.mark(0xB9F8);
            m.push(0x1E); // B9F8 push 0x1e
            m.push(m.di); // B9FA push di
            m.far(.att_41b6, 0xB9FB); // B9FB lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BA00 or ax, ax
            if (m.sf != m.of) continue :sw 0xBA07; // BA02 jl 0xba07
            continue :sw 0xBCF3; // BA04 jmp 0xbcf3
        },
        0xBA07 => {
            m.mark(0xBA07);
            continue :sw 0xB98B; // BA07 jmp 0xb98b
        },
        0xBA0A => {
            m.mark(0xBA0A);
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // BA0A cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xBA50; // BA0F je 0xba50
            m.ww(m.bp +% 0xFFFA, m.add(u16, m.rw(m.bp +% 0xFFFA), 0xD)); // BA11 add word ptr [bp - 6], 0xd
            continue :sw 0xBA15; // falls through
        },
        0xBA15 => {
            m.mark(0xBA15);
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // BA15 inc word ptr [bp - 6]
            continue :sw 0xBA18; // falls through
        },
        0xBA18 => {
            m.mark(0xBA18);
            m.cmp(u16, m.di, 0x1C); // BA18 cmp di, 0x1c
            if (m.zf or m.sf != m.of) continue :sw 0xBA20; // BA1B jle 0xba20
            continue :sw 0xBBF9; // BA1D jmp 0xbbf9
        },
        0xBA20 => {
            m.mark(0xBA20);
            m.cmp(u8, m.rb(m.di +% 0x9F00), 0x0); // BA20 cmp byte ptr [di - 0x6100], 0
            if (!m.zf) continue :sw 0xBA2A; // BA25 jne 0xba2a
            continue :sw 0xBBF9; // BA27 jmp 0xbbf9
        },
        0xBA2A => {
            m.mark(0xBA2A);
            m.cmp(u8, m.rb(m.di +% 0x9F00), 0x8); // BA2A cmp byte ptr [di - 0x6100], 8
            if (m.zf) continue :sw 0xBA34; // BA2F je 0xba34
            continue :sw 0xBBE0; // BA31 jmp 0xbbe0
        },
        0xBA34 => {
            m.mark(0xBA34);
            m.ax = m.rw(0x9356); // BA34 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // BA37 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xBA3F; // BA3A jge 0xba3f
            continue :sw 0xBB90; // BA3C jmp 0xbb90
        },
        0xBA3F => {
            m.mark(0xBA3F);
            m.cmp(u16, m.rw(m.bp +% 0xFFFA), 0x0); // BA3F cmp word ptr [bp - 6], 0
            if (!m.zf) continue :sw 0xBA48; // BA43 jne 0xba48
            continue :sw 0xBBF9; // BA45 jmp 0xbbf9
        },
        0xBA48 => {
            m.mark(0xBA48);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0xC8)); // BA48 sub word ptr [bp - 4], 0xc8
            continue :sw 0xBBF9; // BA4D jmp 0xbbf9
        },
        0xBA50 => {
            m.mark(0xBA50);
            m.si = m.di +% 0x00B0; // BA50 lea si, [di + 0xb0]
            m.bx = m.si; // BA54 mov bx, si
            m.setAl(m.rb(0xA04A)); // BA56 mov al, byte ptr [0xa04a]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // BA59 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // BA5B sub bx, ax
            m.setAl(m.rb(m.bx +% 0x09B8)); // BA5D mov al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // BA61 mov bx, si
            m.setCl(m.rb(0xA04B)); // BA63 mov cl, byte ptr [0xa04b]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // BA67 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // BA69 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // BA6B or al, byte ptr [bx + 0x9b8]
            if (!m.zf) continue :sw 0xBA15; // BA6F jne 0xba15
            m.cmp(u8, m.rb(m.di +% 0x0E16), m.ah()); // BA71 cmp byte ptr [di + 0xe16], ah
            if (m.zf) continue :sw 0xBA90; // BA75 je 0xba90
            m.bx = m.si; // BA77 mov bx, si
            m.setAl(m.rb(0xA04C)); // BA79 mov al, byte ptr [0xa04c]
            m.bx = m.sub(u16, m.bx, m.ax); // BA7C sub bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), m.ah()); // BA7E cmp byte ptr [bx + 0xab6], ah
            if (!m.zf) continue :sw 0xBA87; // BA82 jne 0xba87
            continue :sw 0xBB2A; // BA84 jmp 0xbb2a
        },
        0xBA87 => {
            m.mark(0xBA87);
            m.cmp(u8, m.al(), 0x63); // BA87 cmp al, 0x63
            if (m.cf) continue :sw 0xBA8E; // BA89 jb 0xba8e
            continue :sw 0xBB2A; // BA8B jmp 0xbb2a
        },
        0xBA8E => {
            m.mark(0xBA8E);
            continue :sw 0xBAA6; // BA8E jmp 0xbaa6
        },
        0xBA90 => {
            m.mark(0xBA90);
            m.bx = m.si; // BA90 mov bx, si
            m.setAl(m.rb(0xA04D)); // BA92 mov al, byte ptr [0xa04d]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // BA95 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // BA97 sub bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), m.ah()); // BA99 cmp byte ptr [bx + 0xab6], ah
            if (!m.zf) continue :sw 0xBAA2; // BA9D jne 0xbaa2
            continue :sw 0xBB2A; // BA9F jmp 0xbb2a
        },
        0xBAA2 => {
            m.mark(0xBAA2);
            m.bx = m.si; // BAA2 mov bx, si
            m.bx = m.sub(u16, m.bx, m.ax); // BAA4 sub bx, ax
            continue :sw 0xBAA6; // falls through
        },
        0xBAA6 => {
            m.mark(0xBAA6);
            m.setAl(m.rb(m.bx +% 0x0AB6)); // BAA6 mov al, byte ptr [bx + 0xab6]
            m.cbw(); // BAAA cbw
            m.ww(m.bp +% 0xFFF6, m.ax); // BAAB mov word ptr [bp - 0xa], ax
            m.si = m.ax; // BAAE mov si, ax
            m.si = m.add(u16, m.si, m.di); // BAB0 add si, di
            continue :sw 0xBAB9; // BAB2 jmp 0xbab9
        },
        0xBAB6 => {
            m.mark(0xBAB6);
            m.si = m.add(u16, m.si, m.rw(m.bp +% 0xFFF6)); // BAB6 add si, word ptr [bp - 0xa]
            continue :sw 0xBAB9; // falls through
        },
        0xBAB9 => {
            m.mark(0xBAB9);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // BAB9 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xBAB6; // BABE je 0xbab6
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xA); // BAC0 cmp byte ptr [si - 0x610a], 0xa
            if (!m.zf) continue :sw 0xBB26; // BAC5 jne 0xbb26
            m.ax = m.si; // BAC7 mov ax, si
            m.ax = m.sub(u16, m.ax, m.rw(m.bp +% 0xFFF6)); // BAC9 sub ax, word ptr [bp - 0xa]
            m.cmp(u16, m.ax, m.di); // BACC cmp ax, di
            if (!m.zf) continue :sw 0xBAF2; // BACE jne 0xbaf2
            m.si = m.di; // BAD0 mov si, di
            continue :sw 0xBAD2; // falls through
        },
        0xBAD2 => {
            m.mark(0xBAD2);
            m.si = m.sub(u16, m.si, m.rw(m.bp +% 0xFFF6)); // BAD2 sub si, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // BAD5 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xBAD2; // BADA je 0xbad2
            m.setAl(m.rb(m.si +% 0x9EF6)); // BADC mov al, byte ptr [si - 0x610a]
            m.cbw(); // BAE0 cbw
            m.bx = m.ax; // BAE1 mov bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x1270), 0x0); // BAE3 cmp byte ptr [bx + 0x1270], 0
            if (m.zf) continue :sw 0xBB0F; // BAE8 je 0xbb0f
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0xC8)); // BAEA sub word ptr [bp - 4], 0xc8
            continue :sw 0xB98B; // BAEF jmp 0xb98b
        },
        0xBAF2 => {
            m.mark(0xBAF2);
            m.si = m.di; // BAF2 mov si, di
            continue :sw 0xBAF4; // falls through
        },
        0xBAF4 => {
            m.mark(0xBAF4);
            m.si = m.sub(u16, m.si, m.rw(m.bp +% 0xFFF6)); // BAF4 sub si, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // BAF7 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xBAF4; // BAFC je 0xbaf4
            m.setAl(m.rb(m.si +% 0x9EF6)); // BAFE mov al, byte ptr [si - 0x610a]
            m.cbw(); // BB02 cbw
            m.bx = m.ax; // BB03 mov bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x1270), 0x0); // BB05 cmp byte ptr [bx + 0x1270], 0
            if (m.zf) continue :sw 0xBB0F; // BB0A je 0xbb0f
            continue :sw 0xB98B; // BB0C jmp 0xb98b
        },
        0xBB0F => {
            m.mark(0xBB0F);
            m.ax = m.rw(0xA272); // BB0F mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // BB12 cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xBB1A; // BB15 jle 0xbb1a
            continue :sw 0xBA15; // BB17 jmp 0xba15
        },
        0xBB1A => {
            m.mark(0xBB1A);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x64)); // BB1A sub word ptr [bp - 2], 0x64
            m.bx = m.rw(m.bp +% 0x000A); // BB1E mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // BB21 inc byte ptr [bx]
            continue :sw 0xBA15; // BB23 jmp 0xba15
        },
        0xBB26 => {
            m.mark(0xBB26);
            m.si = m.di +% 0x00B0; // BB26 lea si, [di + 0xb0]
            continue :sw 0xBB2A; // falls through
        },
        0xBB2A => {
            m.mark(0xBB2A);
            m.bx = m.si; // BB2A mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // BB2C sub bx, word ptr [bp - 0xc]
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), 0x0); // BB2F cmp byte ptr [bx + 0xab6], 0
            if (m.zf) continue :sw 0xBB6E; // BB34 je 0xbb6e
            m.setAl(m.rb(m.bx +% 0x0AB6)); // BB36 mov al, byte ptr [bx + 0xab6]
            m.cbw(); // BB3A cbw
            m.ww(m.bp +% 0xFFF6, m.ax); // BB3B mov word ptr [bp - 0xa], ax
            m.ax = m.add(u16, m.ax, m.di); // BB3E add ax, di
            m.si = m.ax; // BB40 mov si, ax
            continue :sw 0xBB47; // BB42 jmp 0xbb47
        },
        0xBB44 => {
            m.mark(0xBB44);
            m.si = m.add(u16, m.si, m.rw(m.bp +% 0xFFF6)); // BB44 add si, word ptr [bp - 0xa]
            continue :sw 0xBB47; // falls through
        },
        0xBB47 => {
            m.mark(0xBB47);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // BB47 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xBB44; // BB4C je 0xbb44
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xC); // BB4E cmp byte ptr [si - 0x610a], 0xc
            if (!m.zf) continue :sw 0xBB6A; // BB53 jne 0xbb6a
            m.push(0x1E); // BB55 push 0x1e
            m.push(m.di); // BB57 push di
            m.far(.att_41b6, 0xBB58); // BB58 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BB5D or ax, ax
            if (m.sf != m.of) continue :sw 0xBB64; // BB5F jl 0xbb64
            continue :sw 0xBCF3; // BB61 jmp 0xbcf3
        },
        0xBB64 => {
            m.mark(0xBB64);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // BB64 inc word ptr [bp - 8]
            continue :sw 0xBA18; // BB67 jmp 0xba18
        },
        0xBB6A => {
            m.mark(0xBB6A);
            m.si = m.di +% 0x00B0; // BB6A lea si, [di + 0xb0]
            continue :sw 0xBB6E; // falls through
        },
        0xBB6E => {
            m.mark(0xBB6E);
            m.bx = m.di; // BB6E mov bx, di
            m.setAl(m.rb(0xA051)); // BB70 mov al, byte ptr [0xa051]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // BB73 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // BB75 sub bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x0CFF), m.ah()); // BB77 cmp byte ptr [bx + 0xcff], ah
            if (m.zf) continue :sw 0xBB98; // BB7B je 0xbb98
            m.push(0x1E); // BB7D push 0x1e
            m.push(m.di); // BB7F push di
            m.far(.att_41b6, 0xBB80); // BB80 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BB85 or ax, ax
            if (m.sf == m.of) continue :sw 0xBB98; // BB87 jge 0xbb98
            m.cmp(u8, m.rb(0xA5F5), 0x0); // BB89 cmp byte ptr [0xa5f5], 0
            if (m.zf) continue :sw 0xBB64; // BB8E je 0xbb64
            continue :sw 0xBB90; // falls through
        },
        0xBB90 => {
            m.mark(0xBB90);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x2BC)); // BB90 sub word ptr [bp - 2], 0x2bc
            continue :sw 0xB950; // BB95 jmp 0xb950
        },
        0xBB98 => {
            m.mark(0xBB98);
            m.bx = m.si; // BB98 mov bx, si
            m.setAl(m.rb(0xA04E)); // BB9A mov al, byte ptr [0xa04e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // BB9D sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // BB9F sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0BB4)); // BBA1 mov al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // BBA5 mov bx, si
            m.setCl(m.rb(0xA04F)); // BBA7 mov cl, byte ptr [0xa04f]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // BBAB sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // BBAD sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // BBAF or al, byte ptr [bx + 0xbb4]
            m.@"test"(u8, m.al(), 0x1); // BBB3 test al, 1
            if (!m.zf) continue :sw 0xBBBA; // BBB5 jne 0xbbba
            continue :sw 0xBCF3; // BBB7 jmp 0xbcf3
        },
        0xBBBA => {
            m.mark(0xBBBA);
            m.push(0x1E); // BBBA push 0x1e
            m.push(m.di); // BBBC push di
            m.far(.att_41b6, 0xBBBD); // BBBD lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BBC2 or ax, ax
            if (m.sf != m.of) continue :sw 0xBBC9; // BBC4 jl 0xbbc9
            continue :sw 0xBCF3; // BBC6 jmp 0xbcf3
        },
        0xBBC9 => {
            m.mark(0xBBC9);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // BBC9 inc word ptr [bp - 8]
            m.ax = m.rw(0xA272); // BBCC mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // BBCF cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xBBD7; // BBD2 jle 0xbbd7
            continue :sw 0xBCF3; // BBD4 jmp 0xbcf3
        },
        0xBBD7 => {
            m.mark(0xBBD7);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xFA)); // BBD7 sub word ptr [bp - 2], 0xfa
            continue :sw 0xB950; // BBDC jmp 0xb950
        },
        0xBBE0 => {
            m.mark(0xBBE0);
            m.cmp(u8, m.rb(m.di +% 0x9F00), 0x7); // BBE0 cmp byte ptr [di - 0x6100], 7
            if (m.sf == m.of) continue :sw 0xBBF9; // BBE5 jge 0xbbf9
            m.ax = m.rw(0xA272); // BBE7 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // BBEA cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xBBF9; // BBED jg 0xbbf9
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x12C)); // BBEF sub word ptr [bp - 2], 0x12c
            m.bx = m.rw(m.bp +% 0x000A); // BBF4 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // BBF7 inc byte ptr [bx]
            continue :sw 0xBBF9; // falls through
        },
        0xBBF9 => {
            m.mark(0xBBF9);
            m.wb(m.di +% 0x9EF6, 0x0); // BBF9 mov byte ptr [di - 0x610a], 0
            m.si = m.di +% 0xFFF6; // BBFE lea si, [di - 0xa]
            continue :sw 0xBC16; // BC01 jmp 0xbc16
        },
        0xBC04 => {
            m.mark(0xBC04);
            m.push(0xF); // BC04 push 0xf
            m.push(m.si); // BC06 push si
            m.far(.att_41b6, 0xBC07); // BC07 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BC0C or ax, ax
            if (m.sf != m.of) continue :sw 0xBC13; // BC0E jl 0xbc13
            continue :sw 0xBCEE; // BC10 jmp 0xbcee
        },
        0xBC13 => {
            m.mark(0xBC13);
            m.si = m.sub(u16, m.si, 0xA); // BC13 sub si, 0xa
            continue :sw 0xBC16; // falls through
        },
        0xBC16 => {
            m.mark(0xBC16);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // BC16 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xBC04; // BC1B je 0xbc04
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // BC1D cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xBC33; // BC22 jle 0xbc33
            m.push(0xF); // BC24 push 0xf
            m.push(m.si); // BC26 push si
            m.far(.att_41b6, 0xBC27); // BC27 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BC2C or ax, ax
            if (m.sf != m.of) continue :sw 0xBC33; // BC2E jl 0xbc33
            continue :sw 0xBCEE; // BC30 jmp 0xbcee
        },
        0xBC33 => {
            m.mark(0xBC33);
            m.si = m.di +% 0xFFFF; // BC33 lea si, [di - 1]
            continue :sw 0xBC48; // BC36 jmp 0xbc48
        },
        0xBC38 => {
            m.mark(0xBC38);
            m.push(0xF); // BC38 push 0xf
            m.push(m.si); // BC3A push si
            m.far(.att_41b6, 0xBC3B); // BC3B lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BC40 or ax, ax
            if (m.sf != m.of) continue :sw 0xBC47; // BC42 jl 0xbc47
            continue :sw 0xBCEE; // BC44 jmp 0xbcee
        },
        0xBC47 => {
            m.mark(0xBC47);
            m.si = m.dec(u16, m.si); // BC47 dec si
            continue :sw 0xBC48; // falls through
        },
        0xBC48 => {
            m.mark(0xBC48);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // BC48 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xBC38; // BC4D je 0xbc38
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // BC4F cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xBC65; // BC54 jle 0xbc65
            m.push(0xF); // BC56 push 0xf
            m.push(m.si); // BC58 push si
            m.far(.att_41b6, 0xBC59); // BC59 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BC5E or ax, ax
            if (m.sf != m.of) continue :sw 0xBC65; // BC60 jl 0xbc65
            continue :sw 0xBCEE; // BC62 jmp 0xbcee
        },
        0xBC65 => {
            m.mark(0xBC65);
            m.si = m.di +% 0x0001; // BC65 lea si, [di + 1]
            continue :sw 0xBC79; // BC68 jmp 0xbc79
        },
        0xBC6C => {
            m.mark(0xBC6C);
            m.push(0xF); // BC6C push 0xf
            m.push(m.si); // BC6E push si
            m.far(.att_41b6, 0xBC6F); // BC6F lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BC74 or ax, ax
            if (m.sf == m.of) continue :sw 0xBCEE; // BC76 jge 0xbcee
            m.si = m.inc(u16, m.si); // BC78 inc si
            continue :sw 0xBC79; // falls through
        },
        0xBC79 => {
            m.mark(0xBC79);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // BC79 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xBC6C; // BC7E je 0xbc6c
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // BC80 cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xBC93; // BC85 jle 0xbc93
            m.push(0xF); // BC87 push 0xf
            m.push(m.si); // BC89 push si
            m.far(.att_41b6, 0xBC8A); // BC8A lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BC8F or ax, ax
            if (m.sf == m.of) continue :sw 0xBCEE; // BC91 jge 0xbcee
            continue :sw 0xBC93; // falls through
        },
        0xBC93 => {
            m.mark(0xBC93);
            m.si = m.di +% 0x000A; // BC93 lea si, [di + 0xa]
            continue :sw 0xBCA7; // BC96 jmp 0xbca7
        },
        0xBC98 => {
            m.mark(0xBC98);
            m.push(0xF); // BC98 push 0xf
            m.push(m.si); // BC9A push si
            m.far(.att_41b6, 0xBC9B); // BC9B lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BCA0 or ax, ax
            if (m.sf == m.of) continue :sw 0xBCEE; // BCA2 jge 0xbcee
            m.si = m.add(u16, m.si, 0xA); // BCA4 add si, 0xa
            continue :sw 0xBCA7; // falls through
        },
        0xBCA7 => {
            m.mark(0xBCA7);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // BCA7 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xBC98; // BCAC je 0xbc98
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // BCAE cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xBCC1; // BCB3 jle 0xbcc1
            m.push(0xF); // BCB5 push 0xf
            m.push(m.si); // BCB7 push si
            m.far(.att_41b6, 0xBCB8); // BCB8 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BCBD or ax, ax
            if (m.sf == m.of) continue :sw 0xBCEE; // BCBF jge 0xbcee
            continue :sw 0xBCC1; // falls through
        },
        0xBCC1 => {
            m.mark(0xBCC1);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x12C)); // BCC1 sub word ptr [bp - 4], 0x12c
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // BCC6 cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xBCDC; // BCCB je 0xbcdc
            m.ax = m.rw(0xA5EC); // BCCD mov ax, word ptr [0xa5ec]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // BCD0 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xBCEE; // BCD3 jge 0xbcee
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x384)); // BCD5 sub word ptr [bp - 2], 0x384
            continue :sw 0xBCE9; // BCDA jmp 0xbce9
        },
        0xBCDC => {
            m.mark(0xBCDC);
            m.ax = m.rw(0x9356); // BCDC mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // BCDF cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xBCEE; // BCE2 jge 0xbcee
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x2BC)); // BCE4 sub word ptr [bp - 2], 0x2bc
            continue :sw 0xBCE9; // falls through
        },
        0xBCE9 => {
            m.mark(0xBCE9);
            m.bx = m.rw(m.bp +% 0x000A); // BCE9 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // BCEC inc byte ptr [bx]
            continue :sw 0xBCEE; // falls through
        },
        0xBCEE => {
            m.mark(0xBCEE);
            m.wb(m.di +% 0x9EF6, 0x4); // BCEE mov byte ptr [di - 0x610a], 4
            continue :sw 0xBCF3; // falls through
        },
        0xBCF3 => {
            m.mark(0xBCF3);
            m.setAl(m.rb(0xA03A)); // BCF3 mov al, byte ptr [0xa03a]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // BCF6 sub ah, ah
            m.di = m.ax; // BCF8 mov di, ax
            m.cmp(u16, m.di, 0x62); // BCFA cmp di, 0x62
            if (m.zf or m.sf != m.of) continue :sw 0xBD02; // BCFD jle 0xbd02
            continue :sw 0xBE81; // BCFF jmp 0xbe81
        },
        0xBD02 => {
            m.mark(0xBD02);
            m.cmp(u8, m.rb(m.di +% 0xA09E), m.ah()); // BD02 cmp byte ptr [di - 0x5f62], ah
            if (!m.zf) continue :sw 0xBD0B; // BD06 jne 0xbd0b
            continue :sw 0xBD96; // BD08 jmp 0xbd96
        },
        0xBD0B => {
            m.mark(0xBD0B);
            m.setAl(m.rb(m.di +% 0xA09E)); // BD0B mov al, byte ptr [di - 0x5f62]
            m.cbw(); // BD0F cbw
            m.bx = m.ax; // BD10 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x047E)); // BD12 mov al, byte ptr [bx + 0x47e]
            m.wb(m.bp +% 0xFFF2, m.al()); // BD16 mov byte ptr [bp - 0xe], al
            m.setAl(m.rb(m.bx +% 0x0490)); // BD19 mov al, byte ptr [bx + 0x490]
            m.cbw(); // BD1D cbw
            m.si = m.ax; // BD1E mov si, ax
            continue :sw 0xBD20; // falls through
        },
        0xBD20 => {
            m.mark(0xBD20);
            m.di = m.add(u16, m.di, m.si); // BD20 add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // BD22 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xBD20; // BD27 je 0xbd20
            m.si = m.di; // BD29 mov si, di
            m.setAl(m.rb(0xA03A)); // BD2B mov al, byte ptr [0xa03a]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // BD2E sub ah, ah
            m.di = m.ax; // BD30 mov di, ax
            m.cx = m.di; // BD32 mov cx, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // BD34 mov al, byte ptr [si - 0x610a]
            m.cbw(); // BD38 cbw
            m.bx = m.ax; // BD39 mov bx, ax
            m.setAl(m.rb(m.bp +% 0xFFF2)); // BD3B mov al, byte ptr [bp - 0xe]
            m.@"test"(u8, m.rb(m.bx +% 0x0470), m.al()); // BD3E test byte ptr [bx + 0x470], al
            if (m.zf) continue :sw 0xBD96; // BD42 je 0xbd96
            m.bx = m.cx; // BD44 mov bx, cx
            m.cmp(u8, m.rb(m.bx +% 0x37DA), m.ch()); // BD46 cmp byte ptr [bx + 0x37da], ch
            if (m.zf) continue :sw 0xBD4F; // BD4A je 0xbd4f
            continue :sw 0xC820; // BD4C jmp 0xc820
        },
        0xBD4F => {
            m.mark(0xBD4F);
            m.push(0x12); // BD4F push 0x12
            m.push(m.di); // BD51 push di
            m.far(.att_41b6, 0xBD52); // BD52 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BD57 or ax, ax
            if (m.sf != m.of) continue :sw 0xBD5E; // BD59 jl 0xbd5e
            continue :sw 0xBE81; // BD5B jmp 0xbe81
        },
        0xBD5E => {
            m.mark(0xBD5E);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // BD5E inc word ptr [bp - 8]
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // BD61 cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xBD6B; // BD66 je 0xbd6b
            continue :sw 0xBE81; // BD68 jmp 0xbe81
        },
        0xBD6B => {
            m.mark(0xBD6B);
            m.cmp(u8, m.rb(0x931A), 0x1); // BD6B cmp byte ptr [0x931a], 1
            if (m.zf or m.sf != m.of) continue :sw 0xBD78; // BD70 jle 0xbd78
            m.ax = 0x80; // BD72 mov ax, 0x80
            continue :sw 0xBD7B; // BD75 jmp 0xbd7b
        },
        0xBD78 => {
            m.mark(0xBD78);
            m.ax = 0x148; // BD78 mov ax, 0x148
            continue :sw 0xBD7B; // falls through
        },
        0xBD7B => {
            m.mark(0xBD7B);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), m.ax)); // BD7B sub word ptr [bp - 4], ax
            m.ax = m.rw(0x9356); // BD7E mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // BD81 cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xBD89; // BD84 jle 0xbd89
            continue :sw 0xBE81; // BD86 jmp 0xbe81
        },
        0xBD89 => {
            m.mark(0xBD89);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x1F4)); // BD89 sub word ptr [bp - 2], 0x1f4
            m.bx = m.rw(m.bp +% 0x000A); // BD8E mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // BD91 inc byte ptr [bx]
            continue :sw 0xBE81; // BD93 jmp 0xbe81
        },
        0xBD96 => {
            m.mark(0xBD96);
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // BD96 cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xBDB6; // BD9B je 0xbdb6
            m.ax = m.rw(0xA272); // BD9D mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // BDA0 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xBDAF; // BDA3 jg 0xbdaf
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xFA)); // BDA5 sub word ptr [bp - 2], 0xfa
            m.bx = m.rw(m.bp +% 0x000A); // BDAA mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // BDAD inc byte ptr [bx]
            continue :sw 0xBDAF; // falls through
        },
        0xBDAF => {
            m.mark(0xBDAF);
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // BDAF inc word ptr [bp - 6]
            continue :sw 0xBE44; // BDB2 jmp 0xbe44
        },
        0xBDB6 => {
            m.mark(0xBDB6);
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // BDB6 cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xBDC0; // BDBB je 0xbdc0
            continue :sw 0xBE81; // BDBD jmp 0xbe81
        },
        0xBDC0 => {
            m.mark(0xBDC0);
            m.si = m.di +% 0x00B0; // BDC0 lea si, [di + 0xb0]
            m.bx = m.si; // BDC4 mov bx, si
            m.setAl(m.rb(0xA04E)); // BDC6 mov al, byte ptr [0xa04e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // BDC9 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // BDCB sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0BB4)); // BDCD mov al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // BDD1 mov bx, si
            m.setCl(m.rb(0xA04F)); // BDD3 mov cl, byte ptr [0xa04f]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // BDD7 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // BDD9 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // BDDB or al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // BDDF mov bx, si
            m.setCl(m.rb(0xA04C)); // BDE1 mov cl, byte ptr [0xa04c]
            m.bx = m.sub(u16, m.bx, m.cx); // BDE5 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // BDE7 or al, byte ptr [bx + 0xab6]
            m.bx = m.si; // BDEB mov bx, si
            m.setCl(m.rb(0xA04D)); // BDED mov cl, byte ptr [0xa04d]
            m.bx = m.sub(u16, m.bx, m.cx); // BDF1 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // BDF3 or al, byte ptr [bx + 0xab6]
            m.bx = m.si; // BDF7 mov bx, si
            m.setCl(m.rb(0xA04A)); // BDF9 mov cl, byte ptr [0xa04a]
            m.bx = m.sub(u16, m.bx, m.cx); // BDFD sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // BDFF or al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // BE03 mov bx, si
            m.setCl(m.rb(0xA04B)); // BE05 mov cl, byte ptr [0xa04b]
            m.bx = m.sub(u16, m.bx, m.cx); // BE09 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // BE0B or al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // BE0F mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // BE11 sub bx, word ptr [bp - 0xc]
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // BE14 or al, byte ptr [bx + 0xbb4]
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // BE18 or al, byte ptr [bx + 0xab6]
            m.bx = m.di; // BE1C mov bx, di
            m.setCl(m.rb(0xA051)); // BE1E mov cl, byte ptr [0xa051]
            m.bx = m.sub(u16, m.bx, m.cx); // BE22 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0CFF))); // BE24 or al, byte ptr [bx + 0xcff]
            if (m.zf) continue :sw 0xBE81; // BE28 je 0xbe81
            m.push(0x12); // BE2A push 0x12
            m.push(m.di); // BE2C push di
            m.far(.att_41b6, 0xBE2D); // BE2D lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BE32 or ax, ax
            if (m.sf == m.of) continue :sw 0xBE81; // BE34 jge 0xbe81
            m.ax = m.rw(0xA272); // BE36 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // BE39 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xBE41; // BE3C jg 0xbe41
            continue :sw 0xBD89; // BE3E jmp 0xbd89
        },
        0xBE41 => {
            m.mark(0xBE41);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // BE41 inc word ptr [bp - 8]
            continue :sw 0xBE44; // falls through
        },
        0xBE44 => {
            m.mark(0xBE44);
            m.setAl(m.xor(u8, m.al(), m.al())); // BE44 xor al, al
            m.wb(0xA03A, m.al()); // BE46 mov byte ptr [0xa03a], al
            m.wb(m.di +% 0x9EF6, m.al()); // BE49 mov byte ptr [di - 0x610a], al
            m.wb(m.bp +% 0xFFEE, m.al()); // BE4D mov byte ptr [bp - 0x12], al
            m.setAl(m.rb(m.di +% 0x9EEE)); // BE50 mov al, byte ptr [di - 0x6112]
            m.cbw(); // BE54 cbw
            m.si = m.ax; // BE55 mov si, ax
            m.cmp(u16, m.ax, 0x6); // BE57 cmp ax, 6
            if (m.sf == m.of) continue :sw 0xBE94; // BE5A jge 0xbe94
            m.cmp(u16, m.ax, 0x1); // BE5C cmp ax, 1
            if (m.zf or m.sf != m.of) continue :sw 0xBE94; // BE5F jle 0xbe94
            m.setAl(m.rb(m.si +% 0x128C)); // BE61 mov al, byte ptr [si + 0x128c]
            m.cbw(); // BE65 cbw
            m.push(m.ax); // BE66 push ax
            m.ax = m.di +% 0xFFF8; // BE67 lea ax, [di - 8]
            m.push(m.ax); // BE6A push ax
            m.far(.att_41b6, 0xBE6B); // BE6B lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BE70 or ax, ax
            if (m.sf == m.of) continue :sw 0xBEE1; // BE72 jge 0xbee1
            continue :sw 0xBE74; // falls through
        },
        0xBE74 => {
            m.mark(0xBE74);
            m.ax = m.di; // BE74 mov ax, di
            m.wb(0xA03A, m.al()); // BE76 mov byte ptr [0xa03a], al
            m.wb(m.di +% 0x9EF6, 0x2); // BE79 mov byte ptr [di - 0x610a], 2
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // BE7E inc word ptr [bp - 8]
            continue :sw 0xBE81; // falls through
        },
        0xBE81 => {
            m.mark(0xBE81);
            m.setAl(m.rb(0xA03B)); // BE81 mov al, byte ptr [0xa03b]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // BE84 sub ah, ah
            m.di = m.ax; // BE86 mov di, ax
            m.cmp(u16, m.di, 0x62); // BE88 cmp di, 0x62
            if (!m.zf and m.sf == m.of) continue :sw 0xBE90; // BE8B jg 0xbe90
            continue :sw 0xC26E; // BE8D jmp 0xc26e
        },
        0xBE90 => {
            m.mark(0xBE90);
            continue :sw 0xC3EF; // BE90 jmp 0xc3ef
        },
        0xBE94 => {
            m.mark(0xBE94);
            m.cmp(u16, m.si, 0x1); // BE94 cmp si, 1
            if (!m.zf) continue :sw 0xBEC0; // BE97 jne 0xbec0
            m.push(0x6); // BE99 push 6
            m.ax = m.di +% 0xFFF8; // BE9B lea ax, [di - 8]
            m.push(m.ax); // BE9E push ax
            m.far(.att_41b6, 0xBE9F); // BE9F lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BEA4 or ax, ax
            if (m.sf == m.of) continue :sw 0xBEE1; // BEA6 jge 0xbee1
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // BEA8 sub word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // BEAC mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // BEAF cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xBEE1; // BEB2 jge 0xbee1
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // BEB4 sub word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // BEB9 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // BEBC inc byte ptr [bx]
            continue :sw 0xBEE1; // BEBE jmp 0xbee1
        },
        0xBEC0 => {
            m.mark(0xBEC0);
            m.cmp(u16, m.si, 0x8); // BEC0 cmp si, 8
            if (!m.zf and m.sf == m.of) continue :sw 0xBEDD; // BEC3 jg 0xbedd
            m.si = m.@"or"(u16, m.si, m.si); // BEC5 or si, si
            if (m.zf) continue :sw 0xBECE; // BEC7 je 0xbece
            m.cmp(u16, m.si, 0x8); // BEC9 cmp si, 8
            if (!m.zf) continue :sw 0xBEE1; // BECC jne 0xbee1
            continue :sw 0xBECE; // falls through
        },
        0xBECE => {
            m.mark(0xBECE);
            m.push(0x9); // BECE push 9
            m.ax = m.di +% 0xFFF8; // BED0 lea ax, [di - 8]
            m.push(m.ax); // BED3 push ax
            m.far(.att_41b6, 0xBED4); // BED4 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BED9 or ax, ax
            if (m.sf != m.of) continue :sw 0xBEE1; // BEDB jl 0xbee1
            continue :sw 0xBEDD; // falls through
        },
        0xBEDD => {
            m.mark(0xBEDD);
            m.wb(m.bp +% 0xFFEE, 0x1); // BEDD mov byte ptr [bp - 0x12], 1
            continue :sw 0xBEE1; // falls through
        },
        0xBEE1 => {
            m.mark(0xBEE1);
            m.setAl(m.rb(m.di +% 0x9EEA)); // BEE1 mov al, byte ptr [di - 0x6116]
            m.cbw(); // BEE5 cbw
            m.si = m.ax; // BEE6 mov si, ax
            m.cmp(u16, m.si, 0x6); // BEE8 cmp si, 6
            if (m.sf == m.of) continue :sw 0xBF08; // BEEB jge 0xbf08
            m.cmp(u16, m.si, 0x1); // BEED cmp si, 1
            if (m.zf or m.sf != m.of) continue :sw 0xBF08; // BEF0 jle 0xbf08
            m.setAl(m.rb(m.si +% 0x128C)); // BEF2 mov al, byte ptr [si + 0x128c]
            m.cbw(); // BEF6 cbw
            m.push(m.ax); // BEF7 push ax
            m.ax = m.di +% 0xFFF4; // BEF8 lea ax, [di - 0xc]
            m.push(m.ax); // BEFB push ax
            m.far(.att_41b6, 0xBEFC); // BEFC lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BF01 or ax, ax
            if (m.sf == m.of) continue :sw 0xBF5B; // BF03 jge 0xbf5b
            continue :sw 0xBE74; // BF05 jmp 0xbe74
        },
        0xBF08 => {
            m.mark(0xBF08);
            m.cmp(u16, m.si, 0x1); // BF08 cmp si, 1
            if (!m.zf) continue :sw 0xBF34; // BF0B jne 0xbf34
            m.push(0x6); // BF0D push 6
            m.ax = m.di +% 0xFFF4; // BF0F lea ax, [di - 0xc]
            m.push(m.ax); // BF12 push ax
            m.far(.att_41b6, 0xBF13); // BF13 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BF18 or ax, ax
            if (m.sf == m.of) continue :sw 0xBF5B; // BF1A jge 0xbf5b
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // BF1C sub word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // BF20 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // BF23 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xBF5B; // BF26 jge 0xbf5b
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // BF28 sub word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // BF2D mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // BF30 inc byte ptr [bx]
            continue :sw 0xBF5B; // BF32 jmp 0xbf5b
        },
        0xBF34 => {
            m.mark(0xBF34);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // BF34 cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xBF5B; // BF38 jne 0xbf5b
            m.cmp(u16, m.si, 0x8); // BF3A cmp si, 8
            if (!m.zf and m.sf == m.of) continue :sw 0xBF57; // BF3D jg 0xbf57
            m.si = m.@"or"(u16, m.si, m.si); // BF3F or si, si
            if (m.zf) continue :sw 0xBF48; // BF41 je 0xbf48
            m.cmp(u16, m.si, 0x8); // BF43 cmp si, 8
            if (!m.zf) continue :sw 0xBF5B; // BF46 jne 0xbf5b
            continue :sw 0xBF48; // falls through
        },
        0xBF48 => {
            m.mark(0xBF48);
            m.push(0x9); // BF48 push 9
            m.ax = m.di +% 0xFFF4; // BF4A lea ax, [di - 0xc]
            m.push(m.ax); // BF4D push ax
            m.far(.att_41b6, 0xBF4E); // BF4E lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BF53 or ax, ax
            if (m.sf != m.of) continue :sw 0xBF5B; // BF55 jl 0xbf5b
            continue :sw 0xBF57; // falls through
        },
        0xBF57 => {
            m.mark(0xBF57);
            m.wb(m.bp +% 0xFFEE, 0x1); // BF57 mov byte ptr [bp - 0x12], 1
            continue :sw 0xBF5B; // falls through
        },
        0xBF5B => {
            m.mark(0xBF5B);
            m.setAl(m.rb(m.di +% 0x9EFE)); // BF5B mov al, byte ptr [di - 0x6102]
            m.cbw(); // BF5F cbw
            m.si = m.ax; // BF60 mov si, ax
            m.cmp(u16, m.si, 0x6); // BF62 cmp si, 6
            if (m.sf == m.of) continue :sw 0xBF82; // BF65 jge 0xbf82
            m.cmp(u16, m.si, 0x1); // BF67 cmp si, 1
            if (m.zf or m.sf != m.of) continue :sw 0xBF82; // BF6A jle 0xbf82
            m.setAl(m.rb(m.si +% 0x128C)); // BF6C mov al, byte ptr [si + 0x128c]
            m.cbw(); // BF70 cbw
            m.push(m.ax); // BF71 push ax
            m.ax = m.di +% 0x0008; // BF72 lea ax, [di + 8]
            m.push(m.ax); // BF75 push ax
            m.far(.att_41b6, 0xBF76); // BF76 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BF7B or ax, ax
            if (m.sf == m.of) continue :sw 0xBFD5; // BF7D jge 0xbfd5
            continue :sw 0xBE74; // BF7F jmp 0xbe74
        },
        0xBF82 => {
            m.mark(0xBF82);
            m.cmp(u16, m.si, 0x1); // BF82 cmp si, 1
            if (!m.zf) continue :sw 0xBFAE; // BF85 jne 0xbfae
            m.push(0x6); // BF87 push 6
            m.ax = m.di +% 0x0008; // BF89 lea ax, [di + 8]
            m.push(m.ax); // BF8C push ax
            m.far(.att_41b6, 0xBF8D); // BF8D lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BF92 or ax, ax
            if (m.sf == m.of) continue :sw 0xBFD5; // BF94 jge 0xbfd5
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // BF96 sub word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // BF9A mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // BF9D cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xBFD5; // BFA0 jge 0xbfd5
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // BFA2 sub word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // BFA7 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // BFAA inc byte ptr [bx]
            continue :sw 0xBFD5; // BFAC jmp 0xbfd5
        },
        0xBFAE => {
            m.mark(0xBFAE);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // BFAE cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xBFD5; // BFB2 jne 0xbfd5
            m.cmp(u16, m.si, 0x8); // BFB4 cmp si, 8
            if (!m.zf and m.sf == m.of) continue :sw 0xBFD1; // BFB7 jg 0xbfd1
            m.si = m.@"or"(u16, m.si, m.si); // BFB9 or si, si
            if (m.zf) continue :sw 0xBFC2; // BFBB je 0xbfc2
            m.cmp(u16, m.si, 0x8); // BFBD cmp si, 8
            if (!m.zf) continue :sw 0xBFD5; // BFC0 jne 0xbfd5
            continue :sw 0xBFC2; // falls through
        },
        0xBFC2 => {
            m.mark(0xBFC2);
            m.push(0x9); // BFC2 push 9
            m.ax = m.di +% 0x0008; // BFC4 lea ax, [di + 8]
            m.push(m.ax); // BFC7 push ax
            m.far(.att_41b6, 0xBFC8); // BFC8 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BFCD or ax, ax
            if (m.sf != m.of) continue :sw 0xBFD5; // BFCF jl 0xbfd5
            continue :sw 0xBFD1; // falls through
        },
        0xBFD1 => {
            m.mark(0xBFD1);
            m.wb(m.bp +% 0xFFEE, 0x1); // BFD1 mov byte ptr [bp - 0x12], 1
            continue :sw 0xBFD5; // falls through
        },
        0xBFD5 => {
            m.mark(0xBFD5);
            m.setAl(m.rb(m.di +% 0x9F02)); // BFD5 mov al, byte ptr [di - 0x60fe]
            m.cbw(); // BFD9 cbw
            m.si = m.ax; // BFDA mov si, ax
            m.cmp(u16, m.si, 0x6); // BFDC cmp si, 6
            if (m.sf == m.of) continue :sw 0xBFFC; // BFDF jge 0xbffc
            m.cmp(u16, m.si, 0x1); // BFE1 cmp si, 1
            if (m.zf or m.sf != m.of) continue :sw 0xBFFC; // BFE4 jle 0xbffc
            m.setAl(m.rb(m.si +% 0x128C)); // BFE6 mov al, byte ptr [si + 0x128c]
            m.cbw(); // BFEA cbw
            m.push(m.ax); // BFEB push ax
            m.ax = m.di +% 0x000C; // BFEC lea ax, [di + 0xc]
            m.push(m.ax); // BFEF push ax
            m.far(.att_41b6, 0xBFF0); // BFF0 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // BFF5 or ax, ax
            if (m.sf == m.of) continue :sw 0xC04F; // BFF7 jge 0xc04f
            continue :sw 0xBE74; // BFF9 jmp 0xbe74
        },
        0xBFFC => {
            m.mark(0xBFFC);
            m.cmp(u16, m.si, 0x1); // BFFC cmp si, 1
            if (!m.zf) continue :sw 0xC028; // BFFF jne 0xc028
            m.push(0x6); // C001 push 6
            m.ax = m.di +% 0x000C; // C003 lea ax, [di + 0xc]
            m.push(m.ax); // C006 push ax
            m.far(.att_41b6, 0xC007); // C007 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C00C or ax, ax
            if (m.sf == m.of) continue :sw 0xC04F; // C00E jge 0xc04f
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // C010 sub word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // C014 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C017 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xC04F; // C01A jge 0xc04f
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // C01C sub word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // C021 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // C024 inc byte ptr [bx]
            continue :sw 0xC04F; // C026 jmp 0xc04f
        },
        0xC028 => {
            m.mark(0xC028);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // C028 cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xC04F; // C02C jne 0xc04f
            m.cmp(u16, m.si, 0x8); // C02E cmp si, 8
            if (!m.zf and m.sf == m.of) continue :sw 0xC04B; // C031 jg 0xc04b
            m.si = m.@"or"(u16, m.si, m.si); // C033 or si, si
            if (m.zf) continue :sw 0xC03C; // C035 je 0xc03c
            m.cmp(u16, m.si, 0x8); // C037 cmp si, 8
            if (!m.zf) continue :sw 0xC04F; // C03A jne 0xc04f
            continue :sw 0xC03C; // falls through
        },
        0xC03C => {
            m.mark(0xC03C);
            m.push(0x9); // C03C push 9
            m.ax = m.di +% 0x000C; // C03E lea ax, [di + 0xc]
            m.push(m.ax); // C041 push ax
            m.far(.att_41b6, 0xC042); // C042 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C047 or ax, ax
            if (m.sf != m.of) continue :sw 0xC04F; // C049 jl 0xc04f
            continue :sw 0xC04B; // falls through
        },
        0xC04B => {
            m.mark(0xC04B);
            m.wb(m.bp +% 0xFFEE, 0x1); // C04B mov byte ptr [bp - 0x12], 1
            continue :sw 0xC04F; // falls through
        },
        0xC04F => {
            m.mark(0xC04F);
            m.setAl(m.rb(m.di +% 0x9F09)); // C04F mov al, byte ptr [di - 0x60f7]
            m.cbw(); // C053 cbw
            m.si = m.ax; // C054 mov si, ax
            m.cmp(u16, m.si, 0x6); // C056 cmp si, 6
            if (m.sf == m.of) continue :sw 0xC076; // C059 jge 0xc076
            m.cmp(u16, m.si, 0x1); // C05B cmp si, 1
            if (m.zf or m.sf != m.of) continue :sw 0xC076; // C05E jle 0xc076
            m.setAl(m.rb(m.si +% 0x128C)); // C060 mov al, byte ptr [si + 0x128c]
            m.cbw(); // C064 cbw
            m.push(m.ax); // C065 push ax
            m.ax = m.di +% 0x0013; // C066 lea ax, [di + 0x13]
            m.push(m.ax); // C069 push ax
            m.far(.att_41b6, 0xC06A); // C06A lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C06F or ax, ax
            if (m.sf == m.of) continue :sw 0xC0C9; // C071 jge 0xc0c9
            continue :sw 0xBE74; // C073 jmp 0xbe74
        },
        0xC076 => {
            m.mark(0xC076);
            m.cmp(u16, m.si, 0x1); // C076 cmp si, 1
            if (!m.zf) continue :sw 0xC0A2; // C079 jne 0xc0a2
            m.push(0x6); // C07B push 6
            m.ax = m.di +% 0x0013; // C07D lea ax, [di + 0x13]
            m.push(m.ax); // C080 push ax
            m.far(.att_41b6, 0xC081); // C081 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C086 or ax, ax
            if (m.sf == m.of) continue :sw 0xC0C9; // C088 jge 0xc0c9
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // C08A sub word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // C08E mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C091 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xC0C9; // C094 jge 0xc0c9
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // C096 sub word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // C09B mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // C09E inc byte ptr [bx]
            continue :sw 0xC0C9; // C0A0 jmp 0xc0c9
        },
        0xC0A2 => {
            m.mark(0xC0A2);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // C0A2 cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xC0C9; // C0A6 jne 0xc0c9
            m.cmp(u16, m.si, 0x8); // C0A8 cmp si, 8
            if (!m.zf and m.sf == m.of) continue :sw 0xC0C5; // C0AB jg 0xc0c5
            m.si = m.@"or"(u16, m.si, m.si); // C0AD or si, si
            if (m.zf) continue :sw 0xC0B6; // C0AF je 0xc0b6
            m.cmp(u16, m.si, 0x8); // C0B1 cmp si, 8
            if (!m.zf) continue :sw 0xC0C9; // C0B4 jne 0xc0c9
            continue :sw 0xC0B6; // falls through
        },
        0xC0B6 => {
            m.mark(0xC0B6);
            m.push(0x9); // C0B6 push 9
            m.ax = m.di +% 0x0013; // C0B8 lea ax, [di + 0x13]
            m.push(m.ax); // C0BB push ax
            m.far(.att_41b6, 0xC0BC); // C0BC lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C0C1 or ax, ax
            if (m.sf != m.of) continue :sw 0xC0C9; // C0C3 jl 0xc0c9
            continue :sw 0xC0C5; // falls through
        },
        0xC0C5 => {
            m.mark(0xC0C5);
            m.wb(m.bp +% 0xFFEE, 0x1); // C0C5 mov byte ptr [bp - 0x12], 1
            continue :sw 0xC0C9; // falls through
        },
        0xC0C9 => {
            m.mark(0xC0C9);
            m.setAl(m.rb(m.di +% 0x9F0B)); // C0C9 mov al, byte ptr [di - 0x60f5]
            m.cbw(); // C0CD cbw
            m.si = m.ax; // C0CE mov si, ax
            m.cmp(u16, m.si, 0x6); // C0D0 cmp si, 6
            if (m.sf == m.of) continue :sw 0xC0F0; // C0D3 jge 0xc0f0
            m.cmp(u16, m.si, 0x1); // C0D5 cmp si, 1
            if (m.zf or m.sf != m.of) continue :sw 0xC0F0; // C0D8 jle 0xc0f0
            m.setAl(m.rb(m.si +% 0x128C)); // C0DA mov al, byte ptr [si + 0x128c]
            m.cbw(); // C0DE cbw
            m.push(m.ax); // C0DF push ax
            m.ax = m.di +% 0x0015; // C0E0 lea ax, [di + 0x15]
            m.push(m.ax); // C0E3 push ax
            m.far(.att_41b6, 0xC0E4); // C0E4 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C0E9 or ax, ax
            if (m.sf == m.of) continue :sw 0xC143; // C0EB jge 0xc143
            continue :sw 0xBE74; // C0ED jmp 0xbe74
        },
        0xC0F0 => {
            m.mark(0xC0F0);
            m.cmp(u16, m.si, 0x1); // C0F0 cmp si, 1
            if (!m.zf) continue :sw 0xC11C; // C0F3 jne 0xc11c
            m.push(0x6); // C0F5 push 6
            m.ax = m.di +% 0x0015; // C0F7 lea ax, [di + 0x15]
            m.push(m.ax); // C0FA push ax
            m.far(.att_41b6, 0xC0FB); // C0FB lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C100 or ax, ax
            if (m.sf == m.of) continue :sw 0xC143; // C102 jge 0xc143
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // C104 sub word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // C108 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C10B cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xC143; // C10E jge 0xc143
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // C110 sub word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // C115 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // C118 inc byte ptr [bx]
            continue :sw 0xC143; // C11A jmp 0xc143
        },
        0xC11C => {
            m.mark(0xC11C);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // C11C cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xC143; // C120 jne 0xc143
            m.cmp(u16, m.si, 0x8); // C122 cmp si, 8
            if (!m.zf and m.sf == m.of) continue :sw 0xC13F; // C125 jg 0xc13f
            m.si = m.@"or"(u16, m.si, m.si); // C127 or si, si
            if (m.zf) continue :sw 0xC130; // C129 je 0xc130
            m.cmp(u16, m.si, 0x8); // C12B cmp si, 8
            if (!m.zf) continue :sw 0xC143; // C12E jne 0xc143
            continue :sw 0xC130; // falls through
        },
        0xC130 => {
            m.mark(0xC130);
            m.push(0x9); // C130 push 9
            m.ax = m.di +% 0x0015; // C132 lea ax, [di + 0x15]
            m.push(m.ax); // C135 push ax
            m.far(.att_41b6, 0xC136); // C136 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C13B or ax, ax
            if (m.sf != m.of) continue :sw 0xC143; // C13D jl 0xc143
            continue :sw 0xC13F; // falls through
        },
        0xC13F => {
            m.mark(0xC13F);
            m.wb(m.bp +% 0xFFEE, 0x1); // C13F mov byte ptr [bp - 0x12], 1
            continue :sw 0xC143; // falls through
        },
        0xC143 => {
            m.mark(0xC143);
            m.cmp(u16, m.di, 0x30); // C143 cmp di, 0x30
            if (!m.zf and m.sf == m.of) continue :sw 0xC152; // C146 jg 0xc152
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // C148 cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xC152; // C14C jne 0xc152
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x24)); // C14E sub word ptr [bp - 2], 0x24
            continue :sw 0xC152; // falls through
        },
        0xC152 => {
            m.mark(0xC152);
            m.setAl(m.rb(m.di +% 0x9EE3)); // C152 mov al, byte ptr [di - 0x611d]
            m.cbw(); // C156 cbw
            m.si = m.ax; // C157 mov si, ax
            m.cmp(u16, m.si, 0x6); // C159 cmp si, 6
            if (m.sf == m.of) continue :sw 0xC17A; // C15C jge 0xc17a
            m.cmp(u16, m.si, 0x1); // C15E cmp si, 1
            if (m.zf or m.sf != m.of) continue :sw 0xC17A; // C161 jle 0xc17a
            m.setAl(m.rb(m.si +% 0x128C)); // C163 mov al, byte ptr [si + 0x128c]
            m.cbw(); // C167 cbw
            m.push(m.ax); // C168 push ax
            m.ax = m.di +% 0xFFED; // C169 lea ax, [di - 0x13]
            m.push(m.ax); // C16C push ax
            m.far(.att_41b6, 0xC16D); // C16D lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C172 or ax, ax
            if (m.sf == m.of) continue :sw 0xC1CD; // C174 jge 0xc1cd
            continue :sw 0xBE74; // C176 jmp 0xbe74
        },
        0xC17A => {
            m.mark(0xC17A);
            m.cmp(u16, m.si, 0x1); // C17A cmp si, 1
            if (!m.zf) continue :sw 0xC1A6; // C17D jne 0xc1a6
            m.push(0x6); // C17F push 6
            m.ax = m.di +% 0xFFED; // C181 lea ax, [di - 0x13]
            m.push(m.ax); // C184 push ax
            m.far(.att_41b6, 0xC185); // C185 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C18A or ax, ax
            if (m.sf == m.of) continue :sw 0xC1CD; // C18C jge 0xc1cd
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // C18E sub word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // C192 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C195 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xC1CD; // C198 jge 0xc1cd
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // C19A sub word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // C19F mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // C1A2 inc byte ptr [bx]
            continue :sw 0xC1CD; // C1A4 jmp 0xc1cd
        },
        0xC1A6 => {
            m.mark(0xC1A6);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // C1A6 cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xC1CD; // C1AA jne 0xc1cd
            m.cmp(u16, m.si, 0x8); // C1AC cmp si, 8
            if (!m.zf and m.sf == m.of) continue :sw 0xC1C9; // C1AF jg 0xc1c9
            m.si = m.@"or"(u16, m.si, m.si); // C1B1 or si, si
            if (m.zf) continue :sw 0xC1BA; // C1B3 je 0xc1ba
            m.cmp(u16, m.si, 0x8); // C1B5 cmp si, 8
            if (!m.zf) continue :sw 0xC1CD; // C1B8 jne 0xc1cd
            continue :sw 0xC1BA; // falls through
        },
        0xC1BA => {
            m.mark(0xC1BA);
            m.push(0x9); // C1BA push 9
            m.ax = m.di +% 0xFFED; // C1BC lea ax, [di - 0x13]
            m.push(m.ax); // C1BF push ax
            m.far(.att_41b6, 0xC1C0); // C1C0 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C1C5 or ax, ax
            if (m.sf != m.of) continue :sw 0xC1CD; // C1C7 jl 0xc1cd
            continue :sw 0xC1C9; // falls through
        },
        0xC1C9 => {
            m.mark(0xC1C9);
            m.wb(m.bp +% 0xFFEE, 0x1); // C1C9 mov byte ptr [bp - 0x12], 1
            continue :sw 0xC1CD; // falls through
        },
        0xC1CD => {
            m.mark(0xC1CD);
            m.setAl(m.rb(m.di +% 0x9EE1)); // C1CD mov al, byte ptr [di - 0x611f]
            m.cbw(); // C1D1 cbw
            m.si = m.ax; // C1D2 mov si, ax
            m.cmp(u16, m.si, 0x6); // C1D4 cmp si, 6
            if (m.sf == m.of) continue :sw 0xC1F4; // C1D7 jge 0xc1f4
            m.cmp(u16, m.si, 0x1); // C1D9 cmp si, 1
            if (m.zf or m.sf != m.of) continue :sw 0xC1F4; // C1DC jle 0xc1f4
            m.setAl(m.rb(m.si +% 0x128C)); // C1DE mov al, byte ptr [si + 0x128c]
            m.cbw(); // C1E2 cbw
            m.push(m.ax); // C1E3 push ax
            m.ax = m.di +% 0xFFEB; // C1E4 lea ax, [di - 0x15]
            m.push(m.ax); // C1E7 push ax
            m.far(.att_41b6, 0xC1E8); // C1E8 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C1ED or ax, ax
            if (m.sf == m.of) continue :sw 0xC247; // C1EF jge 0xc247
            continue :sw 0xBE74; // C1F1 jmp 0xbe74
        },
        0xC1F4 => {
            m.mark(0xC1F4);
            m.cmp(u16, m.si, 0x1); // C1F4 cmp si, 1
            if (!m.zf) continue :sw 0xC220; // C1F7 jne 0xc220
            m.push(0x6); // C1F9 push 6
            m.ax = m.di +% 0xFFEB; // C1FB lea ax, [di - 0x15]
            m.push(m.ax); // C1FE push ax
            m.far(.att_41b6, 0xC1FF); // C1FF lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C204 or ax, ax
            if (m.sf == m.of) continue :sw 0xC247; // C206 jge 0xc247
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // C208 sub word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // C20C mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C20F cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xC247; // C212 jge 0xc247
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // C214 sub word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // C219 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // C21C inc byte ptr [bx]
            continue :sw 0xC247; // C21E jmp 0xc247
        },
        0xC220 => {
            m.mark(0xC220);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // C220 cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xC247; // C224 jne 0xc247
            m.cmp(u16, m.si, 0x8); // C226 cmp si, 8
            if (!m.zf and m.sf == m.of) continue :sw 0xC243; // C229 jg 0xc243
            m.si = m.@"or"(u16, m.si, m.si); // C22B or si, si
            if (m.zf) continue :sw 0xC234; // C22D je 0xc234
            m.cmp(u16, m.si, 0x8); // C22F cmp si, 8
            if (!m.zf) continue :sw 0xC247; // C232 jne 0xc247
            continue :sw 0xC234; // falls through
        },
        0xC234 => {
            m.mark(0xC234);
            m.push(0x9); // C234 push 9
            m.ax = m.di +% 0xFFEB; // C236 lea ax, [di - 0x15]
            m.push(m.ax); // C239 push ax
            m.far(.att_41b6, 0xC23A); // C23A lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C23F or ax, ax
            if (m.sf != m.of) continue :sw 0xC247; // C241 jl 0xc247
            continue :sw 0xC243; // falls through
        },
        0xC243 => {
            m.mark(0xC243);
            m.wb(m.bp +% 0xFFEE, 0x1); // C243 mov byte ptr [bp - 0x12], 1
            continue :sw 0xC247; // falls through
        },
        0xC247 => {
            m.mark(0xC247);
            m.ax = m.di; // C247 mov ax, di
            m.wb(0xA03A, m.al()); // C249 mov byte ptr [0xa03a], al
            m.wb(m.di +% 0x9EF6, 0x2); // C24C mov byte ptr [di - 0x610a], 2
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // C251 cmp byte ptr [bp - 0x12], 0
            if (m.zf) continue :sw 0xC25A; // C255 je 0xc25a
            continue :sw 0xBE81; // C257 jmp 0xbe81
        },
        0xC25A => {
            m.mark(0xC25A);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x15E)); // C25A sub word ptr [bp - 4], 0x15e
            m.ax = m.rw(0x9356); // C25F mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C262 cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xC26A; // C265 jl 0xc26a
            continue :sw 0xBE81; // C267 jmp 0xbe81
        },
        0xC26A => {
            m.mark(0xC26A);
            continue :sw 0xBD89; // C26A jmp 0xbd89
        },
        0xC26E => {
            m.mark(0xC26E);
            m.cmp(u8, m.rb(m.di +% 0xA09E), 0x0); // C26E cmp byte ptr [di - 0x5f62], 0
            if (!m.zf) continue :sw 0xC278; // C273 jne 0xc278
            continue :sw 0xC304; // C275 jmp 0xc304
        },
        0xC278 => {
            m.mark(0xC278);
            m.setAl(m.rb(m.di +% 0xA09E)); // C278 mov al, byte ptr [di - 0x5f62]
            m.cbw(); // C27C cbw
            m.bx = m.ax; // C27D mov bx, ax
            m.setAl(m.rb(m.bx +% 0x047E)); // C27F mov al, byte ptr [bx + 0x47e]
            m.wb(m.bp +% 0xFFF2, m.al()); // C283 mov byte ptr [bp - 0xe], al
            m.setAl(m.rb(m.bx +% 0x0490)); // C286 mov al, byte ptr [bx + 0x490]
            m.cbw(); // C28A cbw
            m.si = m.ax; // C28B mov si, ax
            continue :sw 0xC28D; // falls through
        },
        0xC28D => {
            m.mark(0xC28D);
            m.di = m.add(u16, m.di, m.si); // C28D add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // C28F cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xC28D; // C294 je 0xc28d
            m.si = m.di; // C296 mov si, di
            m.setAl(m.rb(0xA03B)); // C298 mov al, byte ptr [0xa03b]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // C29B sub ah, ah
            m.di = m.ax; // C29D mov di, ax
            m.cx = m.di; // C29F mov cx, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // C2A1 mov al, byte ptr [si - 0x610a]
            m.cbw(); // C2A5 cbw
            m.bx = m.ax; // C2A6 mov bx, ax
            m.setAl(m.rb(m.bp +% 0xFFF2)); // C2A8 mov al, byte ptr [bp - 0xe]
            m.@"test"(u8, m.rb(m.bx +% 0x0470), m.al()); // C2AB test byte ptr [bx + 0x470], al
            if (m.zf) continue :sw 0xC304; // C2AF je 0xc304
            m.bx = m.cx; // C2B1 mov bx, cx
            m.cmp(u8, m.rb(m.bx +% 0x37DA), m.ch()); // C2B3 cmp byte ptr [bx + 0x37da], ch
            if (m.zf) continue :sw 0xC2BC; // C2B7 je 0xc2bc
            continue :sw 0xC820; // C2B9 jmp 0xc820
        },
        0xC2BC => {
            m.mark(0xC2BC);
            m.push(0x12); // C2BC push 0x12
            m.push(m.di); // C2BE push di
            m.far(.att_41b6, 0xC2BF); // C2BF lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C2C4 or ax, ax
            if (m.sf != m.of) continue :sw 0xC2CB; // C2C6 jl 0xc2cb
            continue :sw 0xC3EF; // C2C8 jmp 0xc3ef
        },
        0xC2CB => {
            m.mark(0xC2CB);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // C2CB inc word ptr [bp - 8]
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // C2CE cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xC2D8; // C2D3 je 0xc2d8
            continue :sw 0xC3EF; // C2D5 jmp 0xc3ef
        },
        0xC2D8 => {
            m.mark(0xC2D8);
            m.cmp(u8, m.rb(0x931A), 0x1); // C2D8 cmp byte ptr [0x931a], 1
            if (m.zf or m.sf != m.of) continue :sw 0xC2E6; // C2DD jle 0xc2e6
            m.ax = 0x80; // C2DF mov ax, 0x80
            continue :sw 0xC2E9; // C2E2 jmp 0xc2e9
        },
        0xC2E6 => {
            m.mark(0xC2E6);
            m.ax = 0x148; // C2E6 mov ax, 0x148
            continue :sw 0xC2E9; // falls through
        },
        0xC2E9 => {
            m.mark(0xC2E9);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), m.ax)); // C2E9 sub word ptr [bp - 4], ax
            m.ax = m.rw(0x9356); // C2EC mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C2EF cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xC2F7; // C2F2 jle 0xc2f7
            continue :sw 0xC3EF; // C2F4 jmp 0xc3ef
        },
        0xC2F7 => {
            m.mark(0xC2F7);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x1F4)); // C2F7 sub word ptr [bp - 2], 0x1f4
            m.bx = m.rw(m.bp +% 0x000A); // C2FC mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // C2FF inc byte ptr [bx]
            continue :sw 0xC3EF; // C301 jmp 0xc3ef
        },
        0xC304 => {
            m.mark(0xC304);
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // C304 cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xC324; // C309 je 0xc324
            m.ax = m.rw(0xA272); // C30B mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C30E cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xC31D; // C311 jg 0xc31d
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xFA)); // C313 sub word ptr [bp - 2], 0xfa
            m.bx = m.rw(m.bp +% 0x000A); // C318 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // C31B inc byte ptr [bx]
            continue :sw 0xC31D; // falls through
        },
        0xC31D => {
            m.mark(0xC31D);
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // C31D inc word ptr [bp - 6]
            continue :sw 0xC3B2; // C320 jmp 0xc3b2
        },
        0xC324 => {
            m.mark(0xC324);
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // C324 cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xC32E; // C329 je 0xc32e
            continue :sw 0xC3EF; // C32B jmp 0xc3ef
        },
        0xC32E => {
            m.mark(0xC32E);
            m.si = m.di +% 0x00B0; // C32E lea si, [di + 0xb0]
            m.bx = m.si; // C332 mov bx, si
            m.setAl(m.rb(0xA04E)); // C334 mov al, byte ptr [0xa04e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // C337 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // C339 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0BB4)); // C33B mov al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // C33F mov bx, si
            m.setCl(m.rb(0xA04F)); // C341 mov cl, byte ptr [0xa04f]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // C345 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // C347 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // C349 or al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // C34D mov bx, si
            m.setCl(m.rb(0xA04C)); // C34F mov cl, byte ptr [0xa04c]
            m.bx = m.sub(u16, m.bx, m.cx); // C353 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // C355 or al, byte ptr [bx + 0xab6]
            m.bx = m.si; // C359 mov bx, si
            m.setCl(m.rb(0xA04D)); // C35B mov cl, byte ptr [0xa04d]
            m.bx = m.sub(u16, m.bx, m.cx); // C35F sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // C361 or al, byte ptr [bx + 0xab6]
            m.bx = m.si; // C365 mov bx, si
            m.setCl(m.rb(0xA04A)); // C367 mov cl, byte ptr [0xa04a]
            m.bx = m.sub(u16, m.bx, m.cx); // C36B sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // C36D or al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // C371 mov bx, si
            m.setCl(m.rb(0xA04B)); // C373 mov cl, byte ptr [0xa04b]
            m.bx = m.sub(u16, m.bx, m.cx); // C377 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // C379 or al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // C37D mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // C37F sub bx, word ptr [bp - 0xc]
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // C382 or al, byte ptr [bx + 0xbb4]
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // C386 or al, byte ptr [bx + 0xab6]
            m.bx = m.di; // C38A mov bx, di
            m.setCl(m.rb(0xA051)); // C38C mov cl, byte ptr [0xa051]
            m.bx = m.sub(u16, m.bx, m.cx); // C390 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0CFF))); // C392 or al, byte ptr [bx + 0xcff]
            if (m.zf) continue :sw 0xC3EF; // C396 je 0xc3ef
            m.push(0x12); // C398 push 0x12
            m.push(m.di); // C39A push di
            m.far(.att_41b6, 0xC39B); // C39B lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C3A0 or ax, ax
            if (m.sf == m.of) continue :sw 0xC3EF; // C3A2 jge 0xc3ef
            m.ax = m.rw(0xA272); // C3A4 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C3A7 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xC3AF; // C3AA jg 0xc3af
            continue :sw 0xC2F7; // C3AC jmp 0xc2f7
        },
        0xC3AF => {
            m.mark(0xC3AF);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // C3AF inc word ptr [bp - 8]
            continue :sw 0xC3B2; // falls through
        },
        0xC3B2 => {
            m.mark(0xC3B2);
            m.setAl(m.xor(u8, m.al(), m.al())); // C3B2 xor al, al
            m.wb(0xA03B, m.al()); // C3B4 mov byte ptr [0xa03b], al
            m.wb(m.di +% 0x9EF6, m.al()); // C3B7 mov byte ptr [di - 0x610a], al
            m.wb(m.bp +% 0xFFEE, m.al()); // C3BB mov byte ptr [bp - 0x12], al
            m.setAl(m.rb(m.di +% 0x9EEE)); // C3BE mov al, byte ptr [di - 0x6112]
            m.cbw(); // C3C2 cbw
            m.si = m.ax; // C3C3 mov si, ax
            m.cmp(u16, m.ax, 0x6); // C3C5 cmp ax, 6
            if (m.sf == m.of) continue :sw 0xC402; // C3C8 jge 0xc402
            m.cmp(u16, m.ax, 0x1); // C3CA cmp ax, 1
            if (m.zf or m.sf != m.of) continue :sw 0xC402; // C3CD jle 0xc402
            m.setAl(m.rb(m.si +% 0x128C)); // C3CF mov al, byte ptr [si + 0x128c]
            m.cbw(); // C3D3 cbw
            m.push(m.ax); // C3D4 push ax
            m.ax = m.di +% 0xFFF8; // C3D5 lea ax, [di - 8]
            m.push(m.ax); // C3D8 push ax
            m.far(.att_41b6, 0xC3D9); // C3D9 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C3DE or ax, ax
            if (m.sf == m.of) continue :sw 0xC44F; // C3E0 jge 0xc44f
            continue :sw 0xC3E2; // falls through
        },
        0xC3E2 => {
            m.mark(0xC3E2);
            m.ax = m.di; // C3E2 mov ax, di
            m.wb(0xA03B, m.al()); // C3E4 mov byte ptr [0xa03b], al
            m.wb(m.di +% 0x9EF6, 0x2); // C3E7 mov byte ptr [di - 0x610a], 2
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // C3EC inc word ptr [bp - 8]
            continue :sw 0xC3EF; // falls through
        },
        0xC3EF => {
            m.mark(0xC3EF);
            m.setAl(m.rb(0xA03C)); // C3EF mov al, byte ptr [0xa03c]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // C3F2 sub ah, ah
            m.di = m.ax; // C3F4 mov di, ax
            m.cmp(u16, m.di, 0x62); // C3F6 cmp di, 0x62
            if (!m.zf and m.sf == m.of) continue :sw 0xC3FE; // C3F9 jg 0xc3fe
            continue :sw 0xC7DC; // C3FB jmp 0xc7dc
        },
        0xC3FE => {
            m.mark(0xC3FE);
            continue :sw 0xCA4C; // C3FE jmp 0xca4c
        },
        0xC402 => {
            m.mark(0xC402);
            m.cmp(u16, m.si, 0x1); // C402 cmp si, 1
            if (!m.zf) continue :sw 0xC42E; // C405 jne 0xc42e
            m.push(0x6); // C407 push 6
            m.ax = m.di +% 0xFFF8; // C409 lea ax, [di - 8]
            m.push(m.ax); // C40C push ax
            m.far(.att_41b6, 0xC40D); // C40D lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C412 or ax, ax
            if (m.sf == m.of) continue :sw 0xC44F; // C414 jge 0xc44f
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // C416 sub word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // C41A mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C41D cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xC44F; // C420 jge 0xc44f
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // C422 sub word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // C427 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // C42A inc byte ptr [bx]
            continue :sw 0xC44F; // C42C jmp 0xc44f
        },
        0xC42E => {
            m.mark(0xC42E);
            m.cmp(u16, m.si, 0x8); // C42E cmp si, 8
            if (!m.zf and m.sf == m.of) continue :sw 0xC44B; // C431 jg 0xc44b
            m.si = m.@"or"(u16, m.si, m.si); // C433 or si, si
            if (m.zf) continue :sw 0xC43C; // C435 je 0xc43c
            m.cmp(u16, m.si, 0x8); // C437 cmp si, 8
            if (!m.zf) continue :sw 0xC44F; // C43A jne 0xc44f
            continue :sw 0xC43C; // falls through
        },
        0xC43C => {
            m.mark(0xC43C);
            m.push(0x9); // C43C push 9
            m.ax = m.di +% 0xFFF8; // C43E lea ax, [di - 8]
            m.push(m.ax); // C441 push ax
            m.far(.att_41b6, 0xC442); // C442 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C447 or ax, ax
            if (m.sf != m.of) continue :sw 0xC44F; // C449 jl 0xc44f
            continue :sw 0xC44B; // falls through
        },
        0xC44B => {
            m.mark(0xC44B);
            m.wb(m.bp +% 0xFFEE, 0x1); // C44B mov byte ptr [bp - 0x12], 1
            continue :sw 0xC44F; // falls through
        },
        0xC44F => {
            m.mark(0xC44F);
            m.setAl(m.rb(m.di +% 0x9EEA)); // C44F mov al, byte ptr [di - 0x6116]
            m.cbw(); // C453 cbw
            m.si = m.ax; // C454 mov si, ax
            m.cmp(u16, m.si, 0x6); // C456 cmp si, 6
            if (m.sf == m.of) continue :sw 0xC476; // C459 jge 0xc476
            m.cmp(u16, m.si, 0x1); // C45B cmp si, 1
            if (m.zf or m.sf != m.of) continue :sw 0xC476; // C45E jle 0xc476
            m.setAl(m.rb(m.si +% 0x128C)); // C460 mov al, byte ptr [si + 0x128c]
            m.cbw(); // C464 cbw
            m.push(m.ax); // C465 push ax
            m.ax = m.di +% 0xFFF4; // C466 lea ax, [di - 0xc]
            m.push(m.ax); // C469 push ax
            m.far(.att_41b6, 0xC46A); // C46A lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C46F or ax, ax
            if (m.sf == m.of) continue :sw 0xC4C9; // C471 jge 0xc4c9
            continue :sw 0xC3E2; // C473 jmp 0xc3e2
        },
        0xC476 => {
            m.mark(0xC476);
            m.cmp(u16, m.si, 0x1); // C476 cmp si, 1
            if (!m.zf) continue :sw 0xC4A2; // C479 jne 0xc4a2
            m.push(0x6); // C47B push 6
            m.ax = m.di +% 0xFFF4; // C47D lea ax, [di - 0xc]
            m.push(m.ax); // C480 push ax
            m.far(.att_41b6, 0xC481); // C481 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C486 or ax, ax
            if (m.sf == m.of) continue :sw 0xC4C9; // C488 jge 0xc4c9
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // C48A sub word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // C48E mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C491 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xC4C9; // C494 jge 0xc4c9
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // C496 sub word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // C49B mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // C49E inc byte ptr [bx]
            continue :sw 0xC4C9; // C4A0 jmp 0xc4c9
        },
        0xC4A2 => {
            m.mark(0xC4A2);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // C4A2 cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xC4C9; // C4A6 jne 0xc4c9
            m.cmp(u16, m.si, 0x8); // C4A8 cmp si, 8
            if (!m.zf and m.sf == m.of) continue :sw 0xC4C5; // C4AB jg 0xc4c5
            m.si = m.@"or"(u16, m.si, m.si); // C4AD or si, si
            if (m.zf) continue :sw 0xC4B6; // C4AF je 0xc4b6
            m.cmp(u16, m.si, 0x8); // C4B1 cmp si, 8
            if (!m.zf) continue :sw 0xC4C9; // C4B4 jne 0xc4c9
            continue :sw 0xC4B6; // falls through
        },
        0xC4B6 => {
            m.mark(0xC4B6);
            m.push(0x9); // C4B6 push 9
            m.ax = m.di +% 0xFFF4; // C4B8 lea ax, [di - 0xc]
            m.push(m.ax); // C4BB push ax
            m.far(.att_41b6, 0xC4BC); // C4BC lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C4C1 or ax, ax
            if (m.sf != m.of) continue :sw 0xC4C9; // C4C3 jl 0xc4c9
            continue :sw 0xC4C5; // falls through
        },
        0xC4C5 => {
            m.mark(0xC4C5);
            m.wb(m.bp +% 0xFFEE, 0x1); // C4C5 mov byte ptr [bp - 0x12], 1
            continue :sw 0xC4C9; // falls through
        },
        0xC4C9 => {
            m.mark(0xC4C9);
            m.setAl(m.rb(m.di +% 0x9EFE)); // C4C9 mov al, byte ptr [di - 0x6102]
            m.cbw(); // C4CD cbw
            m.si = m.ax; // C4CE mov si, ax
            m.cmp(u16, m.si, 0x6); // C4D0 cmp si, 6
            if (m.sf == m.of) continue :sw 0xC4F0; // C4D3 jge 0xc4f0
            m.cmp(u16, m.si, 0x1); // C4D5 cmp si, 1
            if (m.zf or m.sf != m.of) continue :sw 0xC4F0; // C4D8 jle 0xc4f0
            m.setAl(m.rb(m.si +% 0x128C)); // C4DA mov al, byte ptr [si + 0x128c]
            m.cbw(); // C4DE cbw
            m.push(m.ax); // C4DF push ax
            m.ax = m.di +% 0x0008; // C4E0 lea ax, [di + 8]
            m.push(m.ax); // C4E3 push ax
            m.far(.att_41b6, 0xC4E4); // C4E4 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C4E9 or ax, ax
            if (m.sf == m.of) continue :sw 0xC543; // C4EB jge 0xc543
            continue :sw 0xC3E2; // C4ED jmp 0xc3e2
        },
        0xC4F0 => {
            m.mark(0xC4F0);
            m.cmp(u16, m.si, 0x1); // C4F0 cmp si, 1
            if (!m.zf) continue :sw 0xC51C; // C4F3 jne 0xc51c
            m.push(0x6); // C4F5 push 6
            m.ax = m.di +% 0x0008; // C4F7 lea ax, [di + 8]
            m.push(m.ax); // C4FA push ax
            m.far(.att_41b6, 0xC4FB); // C4FB lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C500 or ax, ax
            if (m.sf == m.of) continue :sw 0xC543; // C502 jge 0xc543
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // C504 sub word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // C508 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C50B cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xC543; // C50E jge 0xc543
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // C510 sub word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // C515 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // C518 inc byte ptr [bx]
            continue :sw 0xC543; // C51A jmp 0xc543
        },
        0xC51C => {
            m.mark(0xC51C);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // C51C cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xC543; // C520 jne 0xc543
            m.cmp(u16, m.si, 0x8); // C522 cmp si, 8
            if (!m.zf and m.sf == m.of) continue :sw 0xC53F; // C525 jg 0xc53f
            m.si = m.@"or"(u16, m.si, m.si); // C527 or si, si
            if (m.zf) continue :sw 0xC530; // C529 je 0xc530
            m.cmp(u16, m.si, 0x8); // C52B cmp si, 8
            if (!m.zf) continue :sw 0xC543; // C52E jne 0xc543
            continue :sw 0xC530; // falls through
        },
        0xC530 => {
            m.mark(0xC530);
            m.push(0x9); // C530 push 9
            m.ax = m.di +% 0x0008; // C532 lea ax, [di + 8]
            m.push(m.ax); // C535 push ax
            m.far(.att_41b6, 0xC536); // C536 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C53B or ax, ax
            if (m.sf != m.of) continue :sw 0xC543; // C53D jl 0xc543
            continue :sw 0xC53F; // falls through
        },
        0xC53F => {
            m.mark(0xC53F);
            m.wb(m.bp +% 0xFFEE, 0x1); // C53F mov byte ptr [bp - 0x12], 1
            continue :sw 0xC543; // falls through
        },
        0xC543 => {
            m.mark(0xC543);
            m.setAl(m.rb(m.di +% 0x9F02)); // C543 mov al, byte ptr [di - 0x60fe]
            m.cbw(); // C547 cbw
            m.si = m.ax; // C548 mov si, ax
            m.cmp(u16, m.si, 0x6); // C54A cmp si, 6
            if (m.sf == m.of) continue :sw 0xC56A; // C54D jge 0xc56a
            m.cmp(u16, m.si, 0x1); // C54F cmp si, 1
            if (m.zf or m.sf != m.of) continue :sw 0xC56A; // C552 jle 0xc56a
            m.setAl(m.rb(m.si +% 0x128C)); // C554 mov al, byte ptr [si + 0x128c]
            m.cbw(); // C558 cbw
            m.push(m.ax); // C559 push ax
            m.ax = m.di +% 0x000C; // C55A lea ax, [di + 0xc]
            m.push(m.ax); // C55D push ax
            m.far(.att_41b6, 0xC55E); // C55E lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C563 or ax, ax
            if (m.sf == m.of) continue :sw 0xC5BD; // C565 jge 0xc5bd
            continue :sw 0xC3E2; // C567 jmp 0xc3e2
        },
        0xC56A => {
            m.mark(0xC56A);
            m.cmp(u16, m.si, 0x1); // C56A cmp si, 1
            if (!m.zf) continue :sw 0xC596; // C56D jne 0xc596
            m.push(0x6); // C56F push 6
            m.ax = m.di +% 0x000C; // C571 lea ax, [di + 0xc]
            m.push(m.ax); // C574 push ax
            m.far(.att_41b6, 0xC575); // C575 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C57A or ax, ax
            if (m.sf == m.of) continue :sw 0xC5BD; // C57C jge 0xc5bd
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // C57E sub word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // C582 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C585 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xC5BD; // C588 jge 0xc5bd
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // C58A sub word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // C58F mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // C592 inc byte ptr [bx]
            continue :sw 0xC5BD; // C594 jmp 0xc5bd
        },
        0xC596 => {
            m.mark(0xC596);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // C596 cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xC5BD; // C59A jne 0xc5bd
            m.cmp(u16, m.si, 0x8); // C59C cmp si, 8
            if (!m.zf and m.sf == m.of) continue :sw 0xC5B9; // C59F jg 0xc5b9
            m.si = m.@"or"(u16, m.si, m.si); // C5A1 or si, si
            if (m.zf) continue :sw 0xC5AA; // C5A3 je 0xc5aa
            m.cmp(u16, m.si, 0x8); // C5A5 cmp si, 8
            if (!m.zf) continue :sw 0xC5BD; // C5A8 jne 0xc5bd
            continue :sw 0xC5AA; // falls through
        },
        0xC5AA => {
            m.mark(0xC5AA);
            m.push(0x9); // C5AA push 9
            m.ax = m.di +% 0x000C; // C5AC lea ax, [di + 0xc]
            m.push(m.ax); // C5AF push ax
            m.far(.att_41b6, 0xC5B0); // C5B0 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C5B5 or ax, ax
            if (m.sf != m.of) continue :sw 0xC5BD; // C5B7 jl 0xc5bd
            continue :sw 0xC5B9; // falls through
        },
        0xC5B9 => {
            m.mark(0xC5B9);
            m.wb(m.bp +% 0xFFEE, 0x1); // C5B9 mov byte ptr [bp - 0x12], 1
            continue :sw 0xC5BD; // falls through
        },
        0xC5BD => {
            m.mark(0xC5BD);
            m.setAl(m.rb(m.di +% 0x9F09)); // C5BD mov al, byte ptr [di - 0x60f7]
            m.cbw(); // C5C1 cbw
            m.si = m.ax; // C5C2 mov si, ax
            m.cmp(u16, m.si, 0x6); // C5C4 cmp si, 6
            if (m.sf == m.of) continue :sw 0xC5E4; // C5C7 jge 0xc5e4
            m.cmp(u16, m.si, 0x1); // C5C9 cmp si, 1
            if (m.zf or m.sf != m.of) continue :sw 0xC5E4; // C5CC jle 0xc5e4
            m.setAl(m.rb(m.si +% 0x128C)); // C5CE mov al, byte ptr [si + 0x128c]
            m.cbw(); // C5D2 cbw
            m.push(m.ax); // C5D3 push ax
            m.ax = m.di +% 0x0013; // C5D4 lea ax, [di + 0x13]
            m.push(m.ax); // C5D7 push ax
            m.far(.att_41b6, 0xC5D8); // C5D8 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C5DD or ax, ax
            if (m.sf == m.of) continue :sw 0xC637; // C5DF jge 0xc637
            continue :sw 0xC3E2; // C5E1 jmp 0xc3e2
        },
        0xC5E4 => {
            m.mark(0xC5E4);
            m.cmp(u16, m.si, 0x1); // C5E4 cmp si, 1
            if (!m.zf) continue :sw 0xC610; // C5E7 jne 0xc610
            m.push(0x6); // C5E9 push 6
            m.ax = m.di +% 0x0013; // C5EB lea ax, [di + 0x13]
            m.push(m.ax); // C5EE push ax
            m.far(.att_41b6, 0xC5EF); // C5EF lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C5F4 or ax, ax
            if (m.sf == m.of) continue :sw 0xC637; // C5F6 jge 0xc637
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // C5F8 sub word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // C5FC mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C5FF cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xC637; // C602 jge 0xc637
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // C604 sub word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // C609 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // C60C inc byte ptr [bx]
            continue :sw 0xC637; // C60E jmp 0xc637
        },
        0xC610 => {
            m.mark(0xC610);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // C610 cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xC637; // C614 jne 0xc637
            m.cmp(u16, m.si, 0x8); // C616 cmp si, 8
            if (!m.zf and m.sf == m.of) continue :sw 0xC633; // C619 jg 0xc633
            m.si = m.@"or"(u16, m.si, m.si); // C61B or si, si
            if (m.zf) continue :sw 0xC624; // C61D je 0xc624
            m.cmp(u16, m.si, 0x8); // C61F cmp si, 8
            if (!m.zf) continue :sw 0xC637; // C622 jne 0xc637
            continue :sw 0xC624; // falls through
        },
        0xC624 => {
            m.mark(0xC624);
            m.push(0x9); // C624 push 9
            m.ax = m.di +% 0x0013; // C626 lea ax, [di + 0x13]
            m.push(m.ax); // C629 push ax
            m.far(.att_41b6, 0xC62A); // C62A lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C62F or ax, ax
            if (m.sf != m.of) continue :sw 0xC637; // C631 jl 0xc637
            continue :sw 0xC633; // falls through
        },
        0xC633 => {
            m.mark(0xC633);
            m.wb(m.bp +% 0xFFEE, 0x1); // C633 mov byte ptr [bp - 0x12], 1
            continue :sw 0xC637; // falls through
        },
        0xC637 => {
            m.mark(0xC637);
            m.setAl(m.rb(m.di +% 0x9F0B)); // C637 mov al, byte ptr [di - 0x60f5]
            m.cbw(); // C63B cbw
            m.si = m.ax; // C63C mov si, ax
            m.cmp(u16, m.si, 0x6); // C63E cmp si, 6
            if (m.sf == m.of) continue :sw 0xC65E; // C641 jge 0xc65e
            m.cmp(u16, m.si, 0x1); // C643 cmp si, 1
            if (m.zf or m.sf != m.of) continue :sw 0xC65E; // C646 jle 0xc65e
            m.setAl(m.rb(m.si +% 0x128C)); // C648 mov al, byte ptr [si + 0x128c]
            m.cbw(); // C64C cbw
            m.push(m.ax); // C64D push ax
            m.ax = m.di +% 0x0015; // C64E lea ax, [di + 0x15]
            m.push(m.ax); // C651 push ax
            m.far(.att_41b6, 0xC652); // C652 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C657 or ax, ax
            if (m.sf == m.of) continue :sw 0xC6B1; // C659 jge 0xc6b1
            continue :sw 0xC3E2; // C65B jmp 0xc3e2
        },
        0xC65E => {
            m.mark(0xC65E);
            m.cmp(u16, m.si, 0x1); // C65E cmp si, 1
            if (!m.zf) continue :sw 0xC68A; // C661 jne 0xc68a
            m.push(0x6); // C663 push 6
            m.ax = m.di +% 0x0015; // C665 lea ax, [di + 0x15]
            m.push(m.ax); // C668 push ax
            m.far(.att_41b6, 0xC669); // C669 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C66E or ax, ax
            if (m.sf == m.of) continue :sw 0xC6B1; // C670 jge 0xc6b1
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // C672 sub word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // C676 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C679 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xC6B1; // C67C jge 0xc6b1
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // C67E sub word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // C683 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // C686 inc byte ptr [bx]
            continue :sw 0xC6B1; // C688 jmp 0xc6b1
        },
        0xC68A => {
            m.mark(0xC68A);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // C68A cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xC6B1; // C68E jne 0xc6b1
            m.cmp(u16, m.si, 0x8); // C690 cmp si, 8
            if (!m.zf and m.sf == m.of) continue :sw 0xC6AD; // C693 jg 0xc6ad
            m.si = m.@"or"(u16, m.si, m.si); // C695 or si, si
            if (m.zf) continue :sw 0xC69E; // C697 je 0xc69e
            m.cmp(u16, m.si, 0x8); // C699 cmp si, 8
            if (!m.zf) continue :sw 0xC6B1; // C69C jne 0xc6b1
            continue :sw 0xC69E; // falls through
        },
        0xC69E => {
            m.mark(0xC69E);
            m.push(0x9); // C69E push 9
            m.ax = m.di +% 0x0015; // C6A0 lea ax, [di + 0x15]
            m.push(m.ax); // C6A3 push ax
            m.far(.att_41b6, 0xC6A4); // C6A4 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C6A9 or ax, ax
            if (m.sf != m.of) continue :sw 0xC6B1; // C6AB jl 0xc6b1
            continue :sw 0xC6AD; // falls through
        },
        0xC6AD => {
            m.mark(0xC6AD);
            m.wb(m.bp +% 0xFFEE, 0x1); // C6AD mov byte ptr [bp - 0x12], 1
            continue :sw 0xC6B1; // falls through
        },
        0xC6B1 => {
            m.mark(0xC6B1);
            m.cmp(u16, m.di, 0x30); // C6B1 cmp di, 0x30
            if (!m.zf and m.sf == m.of) continue :sw 0xC6C0; // C6B4 jg 0xc6c0
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // C6B6 cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xC6C0; // C6BA jne 0xc6c0
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x24)); // C6BC sub word ptr [bp - 2], 0x24
            continue :sw 0xC6C0; // falls through
        },
        0xC6C0 => {
            m.mark(0xC6C0);
            m.setAl(m.rb(m.di +% 0x9EE3)); // C6C0 mov al, byte ptr [di - 0x611d]
            m.cbw(); // C6C4 cbw
            m.si = m.ax; // C6C5 mov si, ax
            m.cmp(u16, m.si, 0x6); // C6C7 cmp si, 6
            if (m.sf == m.of) continue :sw 0xC6E8; // C6CA jge 0xc6e8
            m.cmp(u16, m.si, 0x1); // C6CC cmp si, 1
            if (m.zf or m.sf != m.of) continue :sw 0xC6E8; // C6CF jle 0xc6e8
            m.setAl(m.rb(m.si +% 0x128C)); // C6D1 mov al, byte ptr [si + 0x128c]
            m.cbw(); // C6D5 cbw
            m.push(m.ax); // C6D6 push ax
            m.ax = m.di +% 0xFFED; // C6D7 lea ax, [di - 0x13]
            m.push(m.ax); // C6DA push ax
            m.far(.att_41b6, 0xC6DB); // C6DB lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C6E0 or ax, ax
            if (m.sf == m.of) continue :sw 0xC73B; // C6E2 jge 0xc73b
            continue :sw 0xC3E2; // C6E4 jmp 0xc3e2
        },
        0xC6E8 => {
            m.mark(0xC6E8);
            m.cmp(u16, m.si, 0x1); // C6E8 cmp si, 1
            if (!m.zf) continue :sw 0xC714; // C6EB jne 0xc714
            m.push(0x6); // C6ED push 6
            m.ax = m.di +% 0xFFED; // C6EF lea ax, [di - 0x13]
            m.push(m.ax); // C6F2 push ax
            m.far(.att_41b6, 0xC6F3); // C6F3 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C6F8 or ax, ax
            if (m.sf == m.of) continue :sw 0xC73B; // C6FA jge 0xc73b
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // C6FC sub word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // C700 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C703 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xC73B; // C706 jge 0xc73b
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // C708 sub word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // C70D mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // C710 inc byte ptr [bx]
            continue :sw 0xC73B; // C712 jmp 0xc73b
        },
        0xC714 => {
            m.mark(0xC714);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // C714 cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xC73B; // C718 jne 0xc73b
            m.cmp(u16, m.si, 0x8); // C71A cmp si, 8
            if (!m.zf and m.sf == m.of) continue :sw 0xC737; // C71D jg 0xc737
            m.si = m.@"or"(u16, m.si, m.si); // C71F or si, si
            if (m.zf) continue :sw 0xC728; // C721 je 0xc728
            m.cmp(u16, m.si, 0x8); // C723 cmp si, 8
            if (!m.zf) continue :sw 0xC73B; // C726 jne 0xc73b
            continue :sw 0xC728; // falls through
        },
        0xC728 => {
            m.mark(0xC728);
            m.push(0x9); // C728 push 9
            m.ax = m.di +% 0xFFED; // C72A lea ax, [di - 0x13]
            m.push(m.ax); // C72D push ax
            m.far(.att_41b6, 0xC72E); // C72E lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C733 or ax, ax
            if (m.sf != m.of) continue :sw 0xC73B; // C735 jl 0xc73b
            continue :sw 0xC737; // falls through
        },
        0xC737 => {
            m.mark(0xC737);
            m.wb(m.bp +% 0xFFEE, 0x1); // C737 mov byte ptr [bp - 0x12], 1
            continue :sw 0xC73B; // falls through
        },
        0xC73B => {
            m.mark(0xC73B);
            m.setAl(m.rb(m.di +% 0x9EE1)); // C73B mov al, byte ptr [di - 0x611f]
            m.cbw(); // C73F cbw
            m.si = m.ax; // C740 mov si, ax
            m.cmp(u16, m.si, 0x6); // C742 cmp si, 6
            if (m.sf == m.of) continue :sw 0xC762; // C745 jge 0xc762
            m.cmp(u16, m.si, 0x1); // C747 cmp si, 1
            if (m.zf or m.sf != m.of) continue :sw 0xC762; // C74A jle 0xc762
            m.setAl(m.rb(m.si +% 0x128C)); // C74C mov al, byte ptr [si + 0x128c]
            m.cbw(); // C750 cbw
            m.push(m.ax); // C751 push ax
            m.ax = m.di +% 0xFFEB; // C752 lea ax, [di - 0x15]
            m.push(m.ax); // C755 push ax
            m.far(.att_41b6, 0xC756); // C756 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C75B or ax, ax
            if (m.sf == m.of) continue :sw 0xC7B5; // C75D jge 0xc7b5
            continue :sw 0xC3E2; // C75F jmp 0xc3e2
        },
        0xC762 => {
            m.mark(0xC762);
            m.cmp(u16, m.si, 0x1); // C762 cmp si, 1
            if (!m.zf) continue :sw 0xC78E; // C765 jne 0xc78e
            m.push(0x6); // C767 push 6
            m.ax = m.di +% 0xFFEB; // C769 lea ax, [di - 0x15]
            m.push(m.ax); // C76C push ax
            m.far(.att_41b6, 0xC76D); // C76D lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C772 or ax, ax
            if (m.sf == m.of) continue :sw 0xC7B5; // C774 jge 0xc7b5
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // C776 sub word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // C77A mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C77D cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xC7B5; // C780 jge 0xc7b5
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // C782 sub word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // C787 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // C78A inc byte ptr [bx]
            continue :sw 0xC7B5; // C78C jmp 0xc7b5
        },
        0xC78E => {
            m.mark(0xC78E);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // C78E cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xC7B5; // C792 jne 0xc7b5
            m.cmp(u16, m.si, 0x8); // C794 cmp si, 8
            if (!m.zf and m.sf == m.of) continue :sw 0xC7B1; // C797 jg 0xc7b1
            m.si = m.@"or"(u16, m.si, m.si); // C799 or si, si
            if (m.zf) continue :sw 0xC7A2; // C79B je 0xc7a2
            m.cmp(u16, m.si, 0x8); // C79D cmp si, 8
            if (!m.zf) continue :sw 0xC7B5; // C7A0 jne 0xc7b5
            continue :sw 0xC7A2; // falls through
        },
        0xC7A2 => {
            m.mark(0xC7A2);
            m.push(0x9); // C7A2 push 9
            m.ax = m.di +% 0xFFEB; // C7A4 lea ax, [di - 0x15]
            m.push(m.ax); // C7A7 push ax
            m.far(.att_41b6, 0xC7A8); // C7A8 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C7AD or ax, ax
            if (m.sf != m.of) continue :sw 0xC7B5; // C7AF jl 0xc7b5
            continue :sw 0xC7B1; // falls through
        },
        0xC7B1 => {
            m.mark(0xC7B1);
            m.wb(m.bp +% 0xFFEE, 0x1); // C7B1 mov byte ptr [bp - 0x12], 1
            continue :sw 0xC7B5; // falls through
        },
        0xC7B5 => {
            m.mark(0xC7B5);
            m.ax = m.di; // C7B5 mov ax, di
            m.wb(0xA03B, m.al()); // C7B7 mov byte ptr [0xa03b], al
            m.wb(m.di +% 0x9EF6, 0x2); // C7BA mov byte ptr [di - 0x610a], 2
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // C7BF cmp byte ptr [bp - 0x12], 0
            if (m.zf) continue :sw 0xC7C8; // C7C3 je 0xc7c8
            continue :sw 0xC3EF; // C7C5 jmp 0xc3ef
        },
        0xC7C8 => {
            m.mark(0xC7C8);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x15E)); // C7C8 sub word ptr [bp - 4], 0x15e
            m.ax = m.rw(0x9356); // C7CD mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C7D0 cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xC7D8; // C7D3 jl 0xc7d8
            continue :sw 0xC3EF; // C7D5 jmp 0xc3ef
        },
        0xC7D8 => {
            m.mark(0xC7D8);
            continue :sw 0xC2F7; // C7D8 jmp 0xc2f7
        },
        0xC7DC => {
            m.mark(0xC7DC);
            m.cmp(u8, m.rb(m.di +% 0xA09E), 0x4); // C7DC cmp byte ptr [di - 0x5f62], 4
            if (!m.zf and m.sf == m.of) continue :sw 0xC7E6; // C7E1 jg 0xc7e6
            continue :sw 0xC884; // C7E3 jmp 0xc884
        },
        0xC7E6 => {
            m.mark(0xC7E6);
            m.setAl(m.rb(m.di +% 0xA09E)); // C7E6 mov al, byte ptr [di - 0x5f62]
            m.cbw(); // C7EA cbw
            m.bx = m.ax; // C7EB mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // C7ED mov al, byte ptr [bx + 0x490]
            m.cbw(); // C7F1 cbw
            m.si = m.ax; // C7F2 mov si, ax
            continue :sw 0xC7F4; // falls through
        },
        0xC7F4 => {
            m.mark(0xC7F4);
            m.di = m.add(u16, m.di, m.si); // C7F4 add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // C7F6 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xC7F4; // C7FB je 0xc7f4
            m.si = m.di; // C7FD mov si, di
            m.setAl(m.rb(0xA03C)); // C7FF mov al, byte ptr [0xa03c]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // C802 sub ah, ah
            m.di = m.ax; // C804 mov di, ax
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xB); // C806 cmp byte ptr [si - 0x610a], 0xb
            if (m.sf != m.of) continue :sw 0xC884; // C80B jl 0xc884
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xC); // C80D cmp byte ptr [si - 0x610a], 0xc
            if (!m.zf and m.sf == m.of) continue :sw 0xC884; // C812 jg 0xc884
            m.bx = m.di; // C814 mov bx, di
            m.cmp(u8, m.rb(m.bx +% 0x37DA), m.ah()); // C816 cmp byte ptr [bx + 0x37da], ah
            if (m.zf) continue :sw 0xC83E; // C81A je 0xc83e
            continue :sw 0xC81C; // falls through
        },
        0xC81C => {
            m.mark(0xC81C);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x32)); // C81C sub word ptr [bp - 2], 0x32
            continue :sw 0xC820; // falls through
        },
        0xC820 => {
            m.mark(0xC820);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x1C2)); // C820 sub word ptr [bp - 4], 0x1c2
            m.ax = m.rw(0x9356); // C825 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C828 cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xC830; // C82B jl 0xc830
            continue :sw 0xCD1A; // C82D jmp 0xcd1a
        },
        0xC830 => {
            m.mark(0xC830);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x320)); // C830 sub word ptr [bp - 2], 0x320
            continue :sw 0xC835; // falls through
        },
        0xC835 => {
            m.mark(0xC835);
            m.bx = m.rw(m.bp +% 0x000A); // C835 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // C838 inc byte ptr [bx]
            continue :sw 0xCCA6; // C83A jmp 0xcca6
        },
        0xC83E => {
            m.mark(0xC83E);
            m.push(0x12); // C83E push 0x12
            m.push(m.di); // C840 push di
            m.far(.att_41b6, 0xC841); // C841 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C846 or ax, ax
            if (m.sf != m.of) continue :sw 0xC84D; // C848 jl 0xc84d
            continue :sw 0xCA4C; // C84A jmp 0xca4c
        },
        0xC84D => {
            m.mark(0xC84D);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // C84D inc word ptr [bp - 8]
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // C850 cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xC85A; // C855 je 0xc85a
            continue :sw 0xCA4C; // C857 jmp 0xca4c
        },
        0xC85A => {
            m.mark(0xC85A);
            m.cmp(u8, m.rb(0x931A), 0x1); // C85A cmp byte ptr [0x931a], 1
            if (m.zf or m.sf != m.of) continue :sw 0xC866; // C85F jle 0xc866
            m.ax = 0x80; // C861 mov ax, 0x80
            continue :sw 0xC869; // C864 jmp 0xc869
        },
        0xC866 => {
            m.mark(0xC866);
            m.ax = 0x148; // C866 mov ax, 0x148
            continue :sw 0xC869; // falls through
        },
        0xC869 => {
            m.mark(0xC869);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), m.ax)); // C869 sub word ptr [bp - 4], ax
            m.ax = m.rw(0x9356); // C86C mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C86F cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xC877; // C872 jl 0xc877
            continue :sw 0xCA4C; // C874 jmp 0xca4c
        },
        0xC877 => {
            m.mark(0xC877);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x226)); // C877 sub word ptr [bp - 2], 0x226
            m.bx = m.rw(m.bp +% 0x000A); // C87C mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // C87F inc byte ptr [bx]
            continue :sw 0xCA4C; // C881 jmp 0xca4c
        },
        0xC884 => {
            m.mark(0xC884);
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // C884 cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xC8AC; // C889 je 0xc8ac
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // C88B inc word ptr [bp - 6]
            m.ax = m.rw(0xA272); // C88E mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C891 cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xC899; // C894 jle 0xc899
            continue :sw 0xC942; // C896 jmp 0xc942
        },
        0xC899 => {
            m.mark(0xC899);
            m.setAl(m.rb(m.di +% 0x100A)); // C899 mov al, byte ptr [di + 0x100a]
            m.cbw(); // C89D cbw
            m.bx = m.ax; // C89E mov bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x9EA8), 0x0); // C8A0 cmp byte ptr [bx - 0x6158], 0
            if (m.zf) continue :sw 0xC8AA; // C8A5 je 0xc8aa
            continue :sw 0xC942; // C8A7 jmp 0xc942
        },
        0xC8AA => {
            m.mark(0xC8AA);
            continue :sw 0xC877; // C8AA jmp 0xc877
        },
        0xC8AC => {
            m.mark(0xC8AC);
            m.si = m.di +% 0x00B0; // C8AC lea si, [di + 0xb0]
            m.bx = m.si; // C8B0 mov bx, si
            m.setAl(m.rb(0xA04A)); // C8B2 mov al, byte ptr [0xa04a]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // C8B5 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // C8B7 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x09B8)); // C8B9 mov al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // C8BD mov bx, si
            m.setCl(m.rb(0xA04B)); // C8BF mov cl, byte ptr [0xa04b]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // C8C3 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // C8C5 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // C8C7 or al, byte ptr [bx + 0x9b8]
            if (m.zf) continue :sw 0xC8DA; // C8CB je 0xc8da
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x18)); // C8CD sub word ptr [bp - 2], 0x18
            m.cmp(u8, m.rb(m.di +% 0xA51C), m.ah()); // C8D1 cmp byte ptr [di - 0x5ae4], ah
            if (m.zf) continue :sw 0xC925; // C8D5 je 0xc925
            continue :sw 0xCA4C; // C8D7 jmp 0xca4c
        },
        0xC8DA => {
            m.mark(0xC8DA);
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // C8DA cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xC8E4; // C8DF je 0xc8e4
            continue :sw 0xCA4C; // C8E1 jmp 0xca4c
        },
        0xC8E4 => {
            m.mark(0xC8E4);
            m.bx = m.si; // C8E4 mov bx, si
            m.setAl(m.rb(0xA04E)); // C8E6 mov al, byte ptr [0xa04e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // C8E9 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // C8EB sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0BB4)); // C8ED mov al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // C8F1 mov bx, si
            m.setCl(m.rb(0xA04F)); // C8F3 mov cl, byte ptr [0xa04f]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // C8F7 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // C8F9 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // C8FB or al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // C8FF mov bx, si
            m.setCl(m.rb(0xA04D)); // C901 mov cl, byte ptr [0xa04d]
            m.bx = m.sub(u16, m.bx, m.cx); // C905 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // C907 or al, byte ptr [bx + 0xab6]
            m.bx = m.di; // C90B mov bx, di
            m.setCl(m.rb(0xA051)); // C90D mov cl, byte ptr [0xa051]
            m.bx = m.sub(u16, m.bx, m.cx); // C911 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0CFF))); // C913 or al, byte ptr [bx + 0xcff]
            m.bx = m.si; // C917 mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // C919 sub bx, word ptr [bp - 0xc]
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // C91C or al, byte ptr [bx + 0xbb4]
            if (!m.zf) continue :sw 0xC925; // C920 jne 0xc925
            continue :sw 0xCA4C; // C922 jmp 0xca4c
        },
        0xC925 => {
            m.mark(0xC925);
            m.push(0x12); // C925 push 0x12
            m.push(m.di); // C927 push di
            m.far(.att_41b6, 0xC928); // C928 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C92D or ax, ax
            if (m.sf != m.of) continue :sw 0xC934; // C92F jl 0xc934
            continue :sw 0xCA4C; // C931 jmp 0xca4c
        },
        0xC934 => {
            m.mark(0xC934);
            m.ax = m.rw(0xA272); // C934 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // C937 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xC93F; // C93A jg 0xc93f
            continue :sw 0xC877; // C93C jmp 0xc877
        },
        0xC93F => {
            m.mark(0xC93F);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // C93F inc word ptr [bp - 8]
            continue :sw 0xC942; // falls through
        },
        0xC942 => {
            m.mark(0xC942);
            m.wb(m.di +% 0x9EF6, 0x0); // C942 mov byte ptr [di - 0x610a], 0
            m.si = m.di +% 0xFFF7; // C947 lea si, [di - 9]
            continue :sw 0xC95E; // C94A jmp 0xc95e
        },
        0xC94C => {
            m.mark(0xC94C);
            m.push(0x9); // C94C push 9
            m.push(m.si); // C94E push si
            m.far(.att_41b6, 0xC94F); // C94F lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C954 or ax, ax
            if (m.sf != m.of) continue :sw 0xC95B; // C956 jl 0xc95b
            continue :sw 0xCA47; // C958 jmp 0xca47
        },
        0xC95B => {
            m.mark(0xC95B);
            m.si = m.sub(u16, m.si, 0x9); // C95B sub si, 9
            continue :sw 0xC95E; // falls through
        },
        0xC95E => {
            m.mark(0xC95E);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // C95E cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xC94C; // C963 je 0xc94c
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // C965 cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xC985; // C96A jle 0xc985
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x8); // C96C cmp byte ptr [si - 0x610a], 8
            if (m.zf or m.sf != m.of) continue :sw 0xC976; // C971 jle 0xc976
            continue :sw 0xCA47; // C973 jmp 0xca47
        },
        0xC976 => {
            m.mark(0xC976);
            m.push(0x9); // C976 push 9
            m.push(m.si); // C978 push si
            m.far(.att_41b6, 0xC979); // C979 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C97E or ax, ax
            if (m.sf != m.of) continue :sw 0xC985; // C980 jl 0xc985
            continue :sw 0xCA47; // C982 jmp 0xca47
        },
        0xC985 => {
            m.mark(0xC985);
            m.si = m.di +% 0xFFF5; // C985 lea si, [di - 0xb]
            continue :sw 0xC99C; // C988 jmp 0xc99c
        },
        0xC98A => {
            m.mark(0xC98A);
            m.push(0x9); // C98A push 9
            m.push(m.si); // C98C push si
            m.far(.att_41b6, 0xC98D); // C98D lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C992 or ax, ax
            if (m.sf != m.of) continue :sw 0xC999; // C994 jl 0xc999
            continue :sw 0xCA47; // C996 jmp 0xca47
        },
        0xC999 => {
            m.mark(0xC999);
            m.si = m.sub(u16, m.si, 0xB); // C999 sub si, 0xb
            continue :sw 0xC99C; // falls through
        },
        0xC99C => {
            m.mark(0xC99C);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // C99C cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xC98A; // C9A1 je 0xc98a
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // C9A3 cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xC9C3; // C9A8 jle 0xc9c3
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x8); // C9AA cmp byte ptr [si - 0x610a], 8
            if (m.zf or m.sf != m.of) continue :sw 0xC9B4; // C9AF jle 0xc9b4
            continue :sw 0xCA47; // C9B1 jmp 0xca47
        },
        0xC9B4 => {
            m.mark(0xC9B4);
            m.push(0x9); // C9B4 push 9
            m.push(m.si); // C9B6 push si
            m.far(.att_41b6, 0xC9B7); // C9B7 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C9BC or ax, ax
            if (m.sf != m.of) continue :sw 0xC9C3; // C9BE jl 0xc9c3
            continue :sw 0xCA47; // C9C0 jmp 0xca47
        },
        0xC9C3 => {
            m.mark(0xC9C3);
            m.si = m.di +% 0x0009; // C9C3 lea si, [di + 9]
            continue :sw 0xC9D9; // C9C6 jmp 0xc9d9
        },
        0xC9CA => {
            m.mark(0xC9CA);
            m.push(0x9); // C9CA push 9
            m.push(m.si); // C9CC push si
            m.far(.att_41b6, 0xC9CD); // C9CD lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C9D2 or ax, ax
            if (m.sf == m.of) continue :sw 0xCA47; // C9D4 jge 0xca47
            m.si = m.add(u16, m.si, 0x9); // C9D6 add si, 9
            continue :sw 0xC9D9; // falls through
        },
        0xC9D9 => {
            m.mark(0xC9D9);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // C9D9 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xC9CA; // C9DE je 0xc9ca
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // C9E0 cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xC9FA; // C9E5 jle 0xc9fa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x8); // C9E7 cmp byte ptr [si - 0x610a], 8
            if (!m.zf and m.sf == m.of) continue :sw 0xCA47; // C9EC jg 0xca47
            m.push(0x9); // C9EE push 9
            m.push(m.si); // C9F0 push si
            m.far(.att_41b6, 0xC9F1); // C9F1 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // C9F6 or ax, ax
            if (m.sf == m.of) continue :sw 0xCA47; // C9F8 jge 0xca47
            continue :sw 0xC9FA; // falls through
        },
        0xC9FA => {
            m.mark(0xC9FA);
            m.si = m.di +% 0x000B; // C9FA lea si, [di + 0xb]
            continue :sw 0xCA0F; // C9FD jmp 0xca0f
        },
        0xCA00 => {
            m.mark(0xCA00);
            m.push(0x9); // CA00 push 9
            m.push(m.si); // CA02 push si
            m.far(.att_41b6, 0xCA03); // CA03 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // CA08 or ax, ax
            if (m.sf == m.of) continue :sw 0xCA47; // CA0A jge 0xca47
            m.si = m.add(u16, m.si, 0xB); // CA0C add si, 0xb
            continue :sw 0xCA0F; // falls through
        },
        0xCA0F => {
            m.mark(0xCA0F);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // CA0F cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xCA00; // CA14 je 0xca00
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // CA16 cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xCA30; // CA1B jle 0xca30
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x8); // CA1D cmp byte ptr [si - 0x610a], 8
            if (!m.zf and m.sf == m.of) continue :sw 0xCA47; // CA22 jg 0xca47
            m.push(0x9); // CA24 push 9
            m.push(m.si); // CA26 push si
            m.far(.att_41b6, 0xCA27); // CA27 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // CA2C or ax, ax
            if (m.sf == m.of) continue :sw 0xCA47; // CA2E jge 0xca47
            continue :sw 0xCA30; // falls through
        },
        0xCA30 => {
            m.mark(0xCA30);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x190)); // CA30 sub word ptr [bp - 4], 0x190
            m.ax = m.rw(0x9356); // CA35 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // CA38 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xCA47; // CA3B jg 0xca47
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x226)); // CA3D sub word ptr [bp - 2], 0x226
            m.bx = m.rw(m.bp +% 0x000A); // CA42 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // CA45 inc byte ptr [bx]
            continue :sw 0xCA47; // falls through
        },
        0xCA47 => {
            m.mark(0xCA47);
            m.wb(m.di +% 0x9EF6, 0x3); // CA47 mov byte ptr [di - 0x610a], 3
            continue :sw 0xCA4C; // falls through
        },
        0xCA4C => {
            m.mark(0xCA4C);
            m.setAl(m.rb(0xA03D)); // CA4C mov al, byte ptr [0xa03d]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // CA4F sub ah, ah
            m.di = m.ax; // CA51 mov di, ax
            m.cmp(u16, m.di, 0x62); // CA53 cmp di, 0x62
            if (m.zf or m.sf != m.of) continue :sw 0xCA5B; // CA56 jle 0xca5b
            continue :sw 0xCCA6; // CA58 jmp 0xcca6
        },
        0xCA5B => {
            m.mark(0xCA5B);
            m.cmp(u8, m.rb(m.di +% 0xA09E), 0x4); // CA5B cmp byte ptr [di - 0x5f62], 4
            if (m.zf or m.sf != m.of) continue :sw 0xCADE; // CA60 jle 0xcade
            m.setAl(m.rb(m.di +% 0xA09E)); // CA62 mov al, byte ptr [di - 0x5f62]
            m.cbw(); // CA66 cbw
            m.bx = m.ax; // CA67 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // CA69 mov al, byte ptr [bx + 0x490]
            m.cbw(); // CA6D cbw
            m.si = m.ax; // CA6E mov si, ax
            continue :sw 0xCA70; // falls through
        },
        0xCA70 => {
            m.mark(0xCA70);
            m.di = m.add(u16, m.di, m.si); // CA70 add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // CA72 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xCA70; // CA77 je 0xca70
            m.si = m.di; // CA79 mov si, di
            m.setAl(m.rb(0xA03D)); // CA7B mov al, byte ptr [0xa03d]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // CA7E sub ah, ah
            m.di = m.ax; // CA80 mov di, ax
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xB); // CA82 cmp byte ptr [si - 0x610a], 0xb
            if (m.sf != m.of) continue :sw 0xCADE; // CA87 jl 0xcade
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xC); // CA89 cmp byte ptr [si - 0x610a], 0xc
            if (!m.zf and m.sf == m.of) continue :sw 0xCADE; // CA8E jg 0xcade
            m.bx = m.di; // CA90 mov bx, di
            m.cmp(u8, m.rb(m.bx +% 0x37DA), m.ah()); // CA92 cmp byte ptr [bx + 0x37da], ah
            if (m.zf) continue :sw 0xCA9B; // CA96 je 0xca9b
            continue :sw 0xC81C; // CA98 jmp 0xc81c
        },
        0xCA9B => {
            m.mark(0xCA9B);
            m.push(0x12); // CA9B push 0x12
            m.push(m.di); // CA9D push di
            m.far(.att_41b6, 0xCA9E); // CA9E lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // CAA3 or ax, ax
            if (m.sf != m.of) continue :sw 0xCAAA; // CAA5 jl 0xcaaa
            continue :sw 0xCCA6; // CAA7 jmp 0xcca6
        },
        0xCAAA => {
            m.mark(0xCAAA);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // CAAA inc word ptr [bp - 8]
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // CAAD cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xCAB7; // CAB2 je 0xcab7
            continue :sw 0xCCA6; // CAB4 jmp 0xcca6
        },
        0xCAB7 => {
            m.mark(0xCAB7);
            m.cmp(u8, m.rb(0x931A), 0x1); // CAB7 cmp byte ptr [0x931a], 1
            if (m.zf or m.sf != m.of) continue :sw 0xCAC4; // CABC jle 0xcac4
            m.ax = 0x80; // CABE mov ax, 0x80
            continue :sw 0xCAC7; // CAC1 jmp 0xcac7
        },
        0xCAC4 => {
            m.mark(0xCAC4);
            m.ax = 0x148; // CAC4 mov ax, 0x148
            continue :sw 0xCAC7; // falls through
        },
        0xCAC7 => {
            m.mark(0xCAC7);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), m.ax)); // CAC7 sub word ptr [bp - 4], ax
            m.ax = m.rw(0x9356); // CACA mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // CACD cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xCAD5; // CAD0 jl 0xcad5
            continue :sw 0xCCA6; // CAD2 jmp 0xcca6
        },
        0xCAD5 => {
            m.mark(0xCAD5);
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x226)); // CAD5 sub word ptr [bp - 2], 0x226
            continue :sw 0xC835; // CADA jmp 0xc835
        },
        0xCADE => {
            m.mark(0xCADE);
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // CADE cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xCB06; // CAE3 je 0xcb06
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // CAE5 inc word ptr [bp - 6]
            m.ax = m.rw(0xA272); // CAE8 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // CAEB cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xCAF3; // CAEE jle 0xcaf3
            continue :sw 0xCB9C; // CAF0 jmp 0xcb9c
        },
        0xCAF3 => {
            m.mark(0xCAF3);
            m.setAl(m.rb(m.di +% 0x100A)); // CAF3 mov al, byte ptr [di + 0x100a]
            m.cbw(); // CAF7 cbw
            m.bx = m.ax; // CAF8 mov bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x9EA8), 0x0); // CAFA cmp byte ptr [bx - 0x6158], 0
            if (m.zf) continue :sw 0xCB04; // CAFF je 0xcb04
            continue :sw 0xCB9C; // CB01 jmp 0xcb9c
        },
        0xCB04 => {
            m.mark(0xCB04);
            continue :sw 0xCAD5; // CB04 jmp 0xcad5
        },
        0xCB06 => {
            m.mark(0xCB06);
            m.si = m.di +% 0x00B0; // CB06 lea si, [di + 0xb0]
            m.bx = m.si; // CB0A mov bx, si
            m.setAl(m.rb(0xA04A)); // CB0C mov al, byte ptr [0xa04a]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // CB0F sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // CB11 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x09B8)); // CB13 mov al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // CB17 mov bx, si
            m.setCl(m.rb(0xA04B)); // CB19 mov cl, byte ptr [0xa04b]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // CB1D sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // CB1F sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // CB21 or al, byte ptr [bx + 0x9b8]
            if (m.zf) continue :sw 0xCB34; // CB25 je 0xcb34
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x18)); // CB27 sub word ptr [bp - 2], 0x18
            m.cmp(u8, m.rb(m.di +% 0xA51C), m.ah()); // CB2B cmp byte ptr [di - 0x5ae4], ah
            if (m.zf) continue :sw 0xCB7F; // CB2F je 0xcb7f
            continue :sw 0xCCA6; // CB31 jmp 0xcca6
        },
        0xCB34 => {
            m.mark(0xCB34);
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // CB34 cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xCB3E; // CB39 je 0xcb3e
            continue :sw 0xCCA6; // CB3B jmp 0xcca6
        },
        0xCB3E => {
            m.mark(0xCB3E);
            m.bx = m.si; // CB3E mov bx, si
            m.setAl(m.rb(0xA04E)); // CB40 mov al, byte ptr [0xa04e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // CB43 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // CB45 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0BB4)); // CB47 mov al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // CB4B mov bx, si
            m.setCl(m.rb(0xA04F)); // CB4D mov cl, byte ptr [0xa04f]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // CB51 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // CB53 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // CB55 or al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // CB59 mov bx, si
            m.setCl(m.rb(0xA04C)); // CB5B mov cl, byte ptr [0xa04c]
            m.bx = m.sub(u16, m.bx, m.cx); // CB5F sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // CB61 or al, byte ptr [bx + 0xab6]
            m.bx = m.di; // CB65 mov bx, di
            m.setCl(m.rb(0xA051)); // CB67 mov cl, byte ptr [0xa051]
            m.bx = m.sub(u16, m.bx, m.cx); // CB6B sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0CFF))); // CB6D or al, byte ptr [bx + 0xcff]
            m.bx = m.si; // CB71 mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // CB73 sub bx, word ptr [bp - 0xc]
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // CB76 or al, byte ptr [bx + 0xbb4]
            if (!m.zf) continue :sw 0xCB7F; // CB7A jne 0xcb7f
            continue :sw 0xCCA6; // CB7C jmp 0xcca6
        },
        0xCB7F => {
            m.mark(0xCB7F);
            m.push(0x12); // CB7F push 0x12
            m.push(m.di); // CB81 push di
            m.far(.att_41b6, 0xCB82); // CB82 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // CB87 or ax, ax
            if (m.sf != m.of) continue :sw 0xCB8E; // CB89 jl 0xcb8e
            continue :sw 0xCCA6; // CB8B jmp 0xcca6
        },
        0xCB8E => {
            m.mark(0xCB8E);
            m.ax = m.rw(0xA272); // CB8E mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // CB91 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xCB99; // CB94 jg 0xcb99
            continue :sw 0xCAD5; // CB96 jmp 0xcad5
        },
        0xCB99 => {
            m.mark(0xCB99);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // CB99 inc word ptr [bp - 8]
            continue :sw 0xCB9C; // falls through
        },
        0xCB9C => {
            m.mark(0xCB9C);
            m.wb(m.di +% 0x9EF6, 0x0); // CB9C mov byte ptr [di - 0x610a], 0
            m.si = m.di +% 0xFFF7; // CBA1 lea si, [di - 9]
            continue :sw 0xCBB8; // CBA4 jmp 0xcbb8
        },
        0xCBA6 => {
            m.mark(0xCBA6);
            m.push(0x9); // CBA6 push 9
            m.push(m.si); // CBA8 push si
            m.far(.att_41b6, 0xCBA9); // CBA9 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // CBAE or ax, ax
            if (m.sf != m.of) continue :sw 0xCBB5; // CBB0 jl 0xcbb5
            continue :sw 0xCCA1; // CBB2 jmp 0xcca1
        },
        0xCBB5 => {
            m.mark(0xCBB5);
            m.si = m.sub(u16, m.si, 0x9); // CBB5 sub si, 9
            continue :sw 0xCBB8; // falls through
        },
        0xCBB8 => {
            m.mark(0xCBB8);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // CBB8 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xCBA6; // CBBD je 0xcba6
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // CBBF cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xCBDF; // CBC4 jle 0xcbdf
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x8); // CBC6 cmp byte ptr [si - 0x610a], 8
            if (m.zf or m.sf != m.of) continue :sw 0xCBD0; // CBCB jle 0xcbd0
            continue :sw 0xCCA1; // CBCD jmp 0xcca1
        },
        0xCBD0 => {
            m.mark(0xCBD0);
            m.push(0x9); // CBD0 push 9
            m.push(m.si); // CBD2 push si
            m.far(.att_41b6, 0xCBD3); // CBD3 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // CBD8 or ax, ax
            if (m.sf != m.of) continue :sw 0xCBDF; // CBDA jl 0xcbdf
            continue :sw 0xCCA1; // CBDC jmp 0xcca1
        },
        0xCBDF => {
            m.mark(0xCBDF);
            m.si = m.di +% 0xFFF5; // CBDF lea si, [di - 0xb]
            continue :sw 0xCBF6; // CBE2 jmp 0xcbf6
        },
        0xCBE4 => {
            m.mark(0xCBE4);
            m.push(0x9); // CBE4 push 9
            m.push(m.si); // CBE6 push si
            m.far(.att_41b6, 0xCBE7); // CBE7 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // CBEC or ax, ax
            if (m.sf != m.of) continue :sw 0xCBF3; // CBEE jl 0xcbf3
            continue :sw 0xCCA1; // CBF0 jmp 0xcca1
        },
        0xCBF3 => {
            m.mark(0xCBF3);
            m.si = m.sub(u16, m.si, 0xB); // CBF3 sub si, 0xb
            continue :sw 0xCBF6; // falls through
        },
        0xCBF6 => {
            m.mark(0xCBF6);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // CBF6 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xCBE4; // CBFB je 0xcbe4
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // CBFD cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xCC1D; // CC02 jle 0xcc1d
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x8); // CC04 cmp byte ptr [si - 0x610a], 8
            if (m.zf or m.sf != m.of) continue :sw 0xCC0E; // CC09 jle 0xcc0e
            continue :sw 0xCCA1; // CC0B jmp 0xcca1
        },
        0xCC0E => {
            m.mark(0xCC0E);
            m.push(0x9); // CC0E push 9
            m.push(m.si); // CC10 push si
            m.far(.att_41b6, 0xCC11); // CC11 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // CC16 or ax, ax
            if (m.sf != m.of) continue :sw 0xCC1D; // CC18 jl 0xcc1d
            continue :sw 0xCCA1; // CC1A jmp 0xcca1
        },
        0xCC1D => {
            m.mark(0xCC1D);
            m.si = m.di +% 0x0009; // CC1D lea si, [di + 9]
            continue :sw 0xCC33; // CC20 jmp 0xcc33
        },
        0xCC24 => {
            m.mark(0xCC24);
            m.push(0x9); // CC24 push 9
            m.push(m.si); // CC26 push si
            m.far(.att_41b6, 0xCC27); // CC27 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // CC2C or ax, ax
            if (m.sf == m.of) continue :sw 0xCCA1; // CC2E jge 0xcca1
            m.si = m.add(u16, m.si, 0x9); // CC30 add si, 9
            continue :sw 0xCC33; // falls through
        },
        0xCC33 => {
            m.mark(0xCC33);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // CC33 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xCC24; // CC38 je 0xcc24
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // CC3A cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xCC54; // CC3F jle 0xcc54
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x8); // CC41 cmp byte ptr [si - 0x610a], 8
            if (!m.zf and m.sf == m.of) continue :sw 0xCCA1; // CC46 jg 0xcca1
            m.push(0x9); // CC48 push 9
            m.push(m.si); // CC4A push si
            m.far(.att_41b6, 0xCC4B); // CC4B lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // CC50 or ax, ax
            if (m.sf == m.of) continue :sw 0xCCA1; // CC52 jge 0xcca1
            continue :sw 0xCC54; // falls through
        },
        0xCC54 => {
            m.mark(0xCC54);
            m.si = m.di +% 0x000B; // CC54 lea si, [di + 0xb]
            continue :sw 0xCC69; // CC57 jmp 0xcc69
        },
        0xCC5A => {
            m.mark(0xCC5A);
            m.push(0x9); // CC5A push 9
            m.push(m.si); // CC5C push si
            m.far(.att_41b6, 0xCC5D); // CC5D lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // CC62 or ax, ax
            if (m.sf == m.of) continue :sw 0xCCA1; // CC64 jge 0xcca1
            m.si = m.add(u16, m.si, 0xB); // CC66 add si, 0xb
            continue :sw 0xCC69; // falls through
        },
        0xCC69 => {
            m.mark(0xCC69);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // CC69 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xCC5A; // CC6E je 0xcc5a
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // CC70 cmp byte ptr [si - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xCC8A; // CC75 jle 0xcc8a
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x8); // CC77 cmp byte ptr [si - 0x610a], 8
            if (!m.zf and m.sf == m.of) continue :sw 0xCCA1; // CC7C jg 0xcca1
            m.push(0x9); // CC7E push 9
            m.push(m.si); // CC80 push si
            m.far(.att_41b6, 0xCC81); // CC81 lcall 0x4793, 0x41b6
            m.ax = m.@"or"(u16, m.ax, m.ax); // CC86 or ax, ax
            if (m.sf == m.of) continue :sw 0xCCA1; // CC88 jge 0xcca1
            continue :sw 0xCC8A; // falls through
        },
        0xCC8A => {
            m.mark(0xCC8A);
            m.ww(m.bp +% 0xFFFC, m.sub(u16, m.rw(m.bp +% 0xFFFC), 0x190)); // CC8A sub word ptr [bp - 4], 0x190
            m.ax = m.rw(0x9356); // CC8F mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // CC92 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xCCA1; // CC95 jg 0xcca1
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), 0x226)); // CC97 sub word ptr [bp - 2], 0x226
            m.bx = m.rw(m.bp +% 0x000A); // CC9C mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // CC9F inc byte ptr [bx]
            continue :sw 0xCCA1; // falls through
        },
        0xCCA1 => {
            m.mark(0xCCA1);
            m.wb(m.di +% 0x9EF6, 0x3); // CCA1 mov byte ptr [di - 0x610a], 3
            continue :sw 0xCCA6; // falls through
        },
        0xCCA6 => {
            m.mark(0xCCA6);
            m.ax = m.rw(m.bp +% 0xFFF8); // CCA6 mov ax, word ptr [bp - 8]
            m.ww(m.bp +% 0xFFFA, m.add(u16, m.rw(m.bp +% 0xFFFA), m.ax)); // CCA9 add word ptr [bp - 6], ax
            if (m.zf) continue :sw 0xCCDC; // CCAC je 0xccdc
            m.cx = m.rw(0xA272); // CCAE mov cx, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.cx); // CCB2 cmp word ptr [bp + 6], cx
            if (!m.zf and m.sf == m.of) continue :sw 0xCCDC; // CCB5 jg 0xccdc
            m.cmp(u16, m.rw(m.bp +% 0xFFFA), 0x1); // CCB7 cmp word ptr [bp - 6], 1
            if (!m.zf and m.sf == m.of) continue :sw 0xCCC9; // CCBB jg 0xccc9
            m.ax = m.@"or"(u16, m.ax, m.ax); // CCBD or ax, ax
            if (m.zf) continue :sw 0xCCDC; // CCBF je 0xccdc
            m.cmp(u16, m.rw(0x378E), 0x1B58); // CCC1 cmp word ptr [0x378e], 0x1b58
            if (!m.cf) continue :sw 0xCCDC; // CCC7 jae 0xccdc
            continue :sw 0xCCC9; // falls through
        },
        0xCCC9 => {
            m.mark(0xCCC9);
            m.bx = m.rw(m.bp +% 0x000A); // CCC9 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // CCCC inc byte ptr [bx]
            m.cmp(u16, m.rw(m.bp +% 0x0008), 0x1); // CCCE cmp word ptr [bp + 8], 1
            m.ax = m.sbb(u16, m.ax, m.ax); // CCD2 sbb ax, ax
            m.setAl(m.@"and"(u8, m.al(), 0x38)); // CCD4 and al, 0x38
            m.ax = m.add(u16, m.ax, 0x1F4); // CCD6 add ax, 0x1f4
            m.ww(m.bp +% 0xFFFE, m.sub(u16, m.rw(m.bp +% 0xFFFE), m.ax)); // CCD9 sub word ptr [bp - 2], ax
            continue :sw 0xCCDC; // falls through
        },
        0xCCDC => {
            m.mark(0xCCDC);
            m.bx = m.rw(m.bp +% 0x000A); // CCDC mov bx, word ptr [bp + 0xa]
            m.cmp(u8, m.rb(m.bx), 0x1); // CCDF cmp byte ptr [bx], 1
            if (!m.zf) continue :sw 0xCCEA; // CCE2 jne 0xccea
            m.ax = m.rw(m.bp +% 0xFFFC); // CCE4 mov ax, word ptr [bp - 4]
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), m.ax)); // CCE7 add word ptr [bp - 2], ax
            continue :sw 0xCCEA; // falls through
        },
        0xCCEA => {
            m.mark(0xCCEA);
            m.@"test"(u8, m.rb(0xA5F5), 0x10); // CCEA test byte ptr [0xa5f5], 0x10
            if (m.zf) continue :sw 0xCCF4; // CCEF je 0xccf4
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // CCF1 inc word ptr [bp - 6]
            continue :sw 0xCCF4; // falls through
        },
        0xCCF4 => {
            m.mark(0xCCF4);
            m.cmp(u16, m.rw(m.bp +% 0xFFFA), 0x0); // CCF4 cmp word ptr [bp - 6], 0
            if (!m.zf) continue :sw 0xCCFD; // CCF8 jne 0xccfd
            continue :sw 0xAD97; // CCFA jmp 0xad97
        },
        0xCCFD => {
            m.mark(0xCCFD);
            m.ax = m.rw(m.bp +% 0xFFFE); // CCFD mov ax, word ptr [bp - 2]
            m.bx = m.rw(m.bp +% 0xFFFA); // CD00 mov bx, word ptr [bp - 6]
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0x0008)); // CD03 sub bx, word ptr [bp + 8]
            m.bx = m.shl(u16, m.bx, 0x1); // CD06 shl bx, 1
            m.ax = m.sub(u16, m.ax, m.rw(m.bx +% 0x0388)); // CD08 sub ax, word ptr [bx + 0x388]
            m.bx = m.rw(m.bp +% 0x0008); // CD0C mov bx, word ptr [bp + 8]
            m.bx = m.shl(u16, m.bx, 0x1); // CD0F shl bx, 1
            m.ax = m.sub(u16, m.ax, m.rw(m.bx +% 0x03EA)); // CD11 sub ax, word ptr [bx + 0x3ea]
            m.si = m.pop(); // CD15 pop si
            m.di = m.pop(); // CD16 pop di
            m.sp = m.bp;
            m.bp = m.pop(); // CD17 leave
            return; // CD18 retf
        },
        0xCD1A => {
            m.mark(0xCD1A);
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // CD1A inc word ptr [bp - 6]
            continue :sw 0xCCA6; // CD1D jmp 0xcca6
        },
        else => unreachable,
    }
}

/// 0EF8:CD20-FA5B, from the label `start` until its `retf` (or, for a near
/// helper entered by `call`, its `ret`).
pub fn runCD20(m: *Machine, start: u16) void {
    @setEvalBranchQuota(1_000_000);
    sw: switch (start) {
        0xCD20 => {
            m.push(m.bp);
            m.bp = m.sp;
            m.sp -%= 0x12; // CD20 enter 0x12, 0
            m.push(m.di); // CD24 push di
            m.push(m.si); // CD25 push si
            m.bx = m.rw(m.bp +% 0x000A); // CD26 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, 0x1); // CD29 mov byte ptr [bx], 1
            m.setAl(m.rb(0xA040)); // CD2C mov al, byte ptr [0xa040]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // CD2F sub ah, ah
            m.ww(m.bp +% 0xFFF4, m.ax); // CD31 mov word ptr [bp - 0xc], ax
            m.cmp(u16, m.ax, 0x62); // CD34 cmp ax, 0x62
            if (m.zf or m.sf != m.of) continue :sw 0xCD60; // CD37 jle 0xcd60
            m.cmp(u8, m.rb(0xA38E), m.ah()); // CD39 cmp byte ptr [0xa38e], ah
            if (m.zf) continue :sw 0xCD4E; // CD3D je 0xcd4e
            m.setAl(m.rb(0xA38E)); // CD3F mov al, byte ptr [0xa38e]
            m.cbw(); // CD42 cbw
            m.bx = m.ax; // CD43 mov bx, ax
            m.setAl(m.rb(m.bx +% 0xA03A)); // CD45 mov al, byte ptr [bx - 0x5fc6]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // CD49 sub ah, ah
            m.ww(m.bp +% 0xFFF4, m.ax); // CD4B mov word ptr [bp - 0xc], ax
            continue :sw 0xCD4E; // falls through
        },
        0xCD4E => {
            m.mark(0xCD4E);
            m.cmp(u8, m.rb(0x931B), 0x0); // CD4E cmp byte ptr [0x931b], 0
            if (!m.zf) continue :sw 0xCD60; // CD53 jne 0xcd60
            m.cmp(u16, m.ax, 0x62); // CD55 cmp ax, 0x62
            if (m.zf or m.sf != m.of) continue :sw 0xCD60; // CD58 jle 0xcd60
            m.ax = m.xor(u16, m.ax, m.ax); // CD5A xor ax, ax
            m.si = m.pop(); // CD5C pop si
            m.di = m.pop(); // CD5D pop di
            m.sp = m.bp;
            m.bp = m.pop(); // CD5E leave
            return; // CD5F retf
        },
        0xCD60 => {
            m.mark(0xCD60);
            m.ax = m.xor(u16, m.ax, m.ax); // CD60 xor ax, ax
            m.ww(m.bp +% 0xFFFE, m.ax); // CD62 mov word ptr [bp - 2], ax
            m.ww(m.bp +% 0xFFFC, m.ax); // CD65 mov word ptr [bp - 4], ax
            m.ww(m.bp +% 0xFFFA, m.ax); // CD68 mov word ptr [bp - 6], ax
            m.ww(m.bp +% 0xFFF8, m.ax); // CD6B mov word ptr [bp - 8], ax
            m.cmp(u8, m.rb(0xA3F4), 0x1); // CD6E cmp byte ptr [0xa3f4], 1
            if (!m.zf and m.sf == m.of) continue :sw 0xCD7A; // CD73 jg 0xcd7a
            m.ww(m.bp +% 0x0006, 0x64); // CD75 mov word ptr [bp + 6], 0x64
            continue :sw 0xCD7A; // falls through
        },
        0xCD7A => {
            m.mark(0xCD7A);
            m.setAl(m.rb(0xA051)); // CD7A mov al, byte ptr [0xa051]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // CD7D sub ah, ah
            m.di = m.ax; // CD7F mov di, ax
            m.cmp(u16, m.di, 0x51); // CD81 cmp di, 0x51
            if (m.sf != m.of) continue :sw 0xCD89; // CD84 jl 0xcd89
            continue :sw 0xCFA2; // CD86 jmp 0xcfa2
        },
        0xCD89 => {
            m.mark(0xCD89);
            m.cmp(u16, m.di, 0x47); // CD89 cmp di, 0x47
            if (m.sf == m.of) continue :sw 0xCD91; // CD8C jge 0xcd91
            continue :sw 0xDAE8; // CD8E jmp 0xdae8
        },
        0xCD91 => {
            m.mark(0xCD91);
            m.cmp(u16, m.di, 0x48); // CD91 cmp di, 0x48
            if (m.zf or m.sf != m.of) continue :sw 0xCD9E; // CD94 jle 0xcd9e
            m.cmp(u16, m.di, 0x4D); // CD96 cmp di, 0x4d
            if (m.sf == m.of) continue :sw 0xCD9E; // CD99 jge 0xcd9e
            continue :sw 0xDAE8; // CD9B jmp 0xdae8
        },
        0xCD9E => {
            m.mark(0xCD9E);
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), 0x63); // CD9E cmp word ptr [bp - 0xc], 0x63
            if (m.sf != m.of) continue :sw 0xCDA7; // CDA2 jl 0xcda7
            continue :sw 0xCF95; // CDA4 jmp 0xcf95
        },
        0xCDA7 => {
            m.mark(0xCDA7);
            m.cmp(u16, m.di, 0x48); // CDA7 cmp di, 0x48
            if (!m.zf and m.sf == m.of) continue :sw 0xCDB2; // CDAA jg 0xcdb2
            m.si = 0x52; // CDAC mov si, 0x52
            continue :sw 0xCDB5; // CDAF jmp 0xcdb5
        },
        0xCDB2 => {
            m.mark(0xCDB2);
            m.si = 0x57; // CDB2 mov si, 0x57
            continue :sw 0xCDB5; // falls through
        },
        0xCDB5 => {
            m.mark(0xCDB5);
            m.ww(m.bp +% 0xFFF6, m.si); // CDB5 mov word ptr [bp - 0xa], si
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // CDB8 cmp byte ptr [si - 0x610a], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xCDC9; // CDBD jg 0xcdc9
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // CDBF cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xCDC9; // CDC4 je 0xcdc9
            continue :sw 0xCEE0; // CDC6 jmp 0xcee0
        },
        0xCDC9 => {
            m.mark(0xCDC9);
            m.bx = m.si; // CDC9 mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // CDCB sub bx, word ptr [bp - 0xc]
            m.setAl(m.rb(m.bx +% 0x0C64)); // CDCE mov al, byte ptr [bx + 0xc64]
            m.cbw(); // CDD2 cbw
            m.di = m.ax; // CDD3 mov di, ax
            m.di = m.@"or"(u16, m.di, m.di); // CDD5 or di, di
            if (!m.zf) continue :sw 0xCDDC; // CDD7 jne 0xcddc
            continue :sw 0xCE9C; // CDD9 jmp 0xce9c
        },
        0xCDDC => {
            m.mark(0xCDDC);
            m.si = m.add(u16, m.si, m.di); // CDDC add si, di
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // CDDE cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xCDDC; // CDE3 je 0xcddc
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // CDE5 cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xCDED; // CDE8 je 0xcded
            continue :sw 0xCEE0; // CDEA jmp 0xcee0
        },
        0xCDED => {
            m.mark(0xCDED);
            m.wb(m.si +% 0x9EF6, 0x0); // CDED mov byte ptr [si - 0x610a], 0
            m.bx = m.rw(m.bp +% 0xFFF6); // CDF2 mov bx, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.bx +% 0x9EF6), 0x0); // CDF5 cmp byte ptr [bx - 0x610a], 0
            if (m.zf) continue :sw 0xCE0E; // CDFA je 0xce0e
            continue :sw 0xCDFC; // falls through
        },
        0xCDFC => {
            m.mark(0xCDFC);
            m.push(0x1B); // CDFC push 0x1b
            m.push(m.bx); // CDFE push bx
            m.far(.see_white, 0xCDFF); // CDFF lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // CE04 or ax, ax
            if (!m.zf and m.sf == m.of) continue :sw 0xCE0B; // CE06 jg 0xce0b
            continue :sw 0xCEDB; // CE08 jmp 0xcedb
        },
        0xCE0B => {
            m.mark(0xCE0B);
            continue :sw 0xCE1F; // CE0B jmp 0xce1f
        },
        0xCE0E => {
            m.mark(0xCE0E);
            m.push(0x1B); // CE0E push 0x1b
            m.push(m.rw(m.bp +% 0xFFF6)); // CE10 push word ptr [bp - 0xa]
            m.far(.see_white, 0xCE13); // CE13 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // CE18 or ax, ax
            if (m.sf != m.of) continue :sw 0xCE56; // CE1A jl 0xce56
            continue :sw 0xCE1C; // falls through
        },
        0xCE1C => {
            m.mark(0xCE1C);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // CE1C inc word ptr [bp - 8]
            continue :sw 0xCE1F; // falls through
        },
        0xCE1F => {
            m.mark(0xCE1F);
            m.wb(m.si +% 0x9EF6, 0x5); // CE1F mov byte ptr [si - 0x610a], 5
            m.setBl(m.rb(0xA051)); // CE24 mov bl, byte ptr [0xa051]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // CE28 sub bh, bh
            m.cmp(u8, m.rb(m.bx +% 0x9EE2), 0x1); // CE2A cmp byte ptr [bx - 0x611e], 1
            if (m.zf) continue :sw 0xCE3E; // CE2F je 0xce3e
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // CE31 sub bx, word ptr [bp - 0xc]
            m.cmp(u8, m.rb(m.bx +% 0x0A68), 0x0); // CE34 cmp byte ptr [bx + 0xa68], 0
            if (!m.zf) continue :sw 0xCE3E; // CE39 jne 0xce3e
            continue :sw 0xDAF6; // CE3B jmp 0xdaf6
        },
        0xCE3E => {
            m.mark(0xCE3E);
            m.ax = m.rw(0x9356); // CE3E mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // CE41 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xCE49; // CE44 jg 0xce49
            continue :sw 0xDB15; // CE46 jmp 0xdb15
        },
        0xCE49 => {
            m.mark(0xCE49);
            m.cmp(u8, m.rb(0xA40E), 0x0); // CE49 cmp byte ptr [0xa40e], 0
            if (!m.zf) continue :sw 0xCE53; // CE4E jne 0xce53
            continue :sw 0xDADC; // CE50 jmp 0xdadc
        },
        0xCE53 => {
            m.mark(0xCE53);
            continue :sw 0xDB15; // CE53 jmp 0xdb15
        },
        0xCE56 => {
            m.mark(0xCE56);
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), 0x51); // CE56 cmp word ptr [bp - 0xc], 0x51
            if (m.sf != m.of) continue :sw 0xCE68; // CE5A jl 0xce68
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), 0x58); // CE5C cmp word ptr [bp - 0xc], 0x58
            if (!m.zf and m.sf == m.of) continue :sw 0xCE68; // CE60 jg 0xce68
            m.ww(m.bp +% 0xFFF6, m.sub(u16, m.rw(m.bp +% 0xFFF6), m.di)); // CE62 sub word ptr [bp - 0xa], di
            continue :sw 0xCE6C; // CE65 jmp 0xce6c
        },
        0xCE68 => {
            m.mark(0xCE68);
            m.ww(m.bp +% 0xFFF6, m.sub(u16, m.rw(m.bp +% 0xFFF6), 0xA)); // CE68 sub word ptr [bp - 0xa], 0xa
            continue :sw 0xCE6C; // falls through
        },
        0xCE6C => {
            m.mark(0xCE6C);
            m.bx = m.rw(m.bp +% 0xFFF6); // CE6C mov bx, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.bx +% 0x9EF6), 0x0); // CE6F cmp byte ptr [bx - 0x610a], 0
            if (!m.zf) continue :sw 0xCE84; // CE74 jne 0xce84
            m.push(0x1B); // CE76 push 0x1b
            m.push(m.bx); // CE78 push bx
            m.far(.see_white, 0xCE79); // CE79 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // CE7E or ax, ax
            if (m.sf != m.of) continue :sw 0xCEDB; // CE80 jl 0xcedb
            continue :sw 0xCE1C; // CE82 jmp 0xce1c
        },
        0xCE84 => {
            m.mark(0xCE84);
            m.bx = m.rw(m.bp +% 0xFFF6); // CE84 mov bx, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.bx +% 0x9EF6), 0x7); // CE87 cmp byte ptr [bx - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xCEDB; // CE8C jle 0xcedb
            m.push(0x1B); // CE8E push 0x1b
            m.push(m.bx); // CE90 push bx
            m.far(.see_white, 0xCE91); // CE91 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // CE96 or ax, ax
            if (!m.zf and m.sf == m.of) continue :sw 0xCE1F; // CE98 jg 0xce1f
            continue :sw 0xCEDB; // CE9A jmp 0xcedb
        },
        0xCE9C => {
            m.mark(0xCE9C);
            m.bx = m.si; // CE9C mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // CE9E sub bx, word ptr [bp - 0xc]
            m.setAl(m.rb(m.bx +% 0x0B66)); // CEA1 mov al, byte ptr [bx + 0xb66]
            m.cbw(); // CEA5 cbw
            m.di = m.ax; // CEA6 mov di, ax
            m.di = m.@"or"(u16, m.di, m.di); // CEA8 or di, di
            if (m.zf) continue :sw 0xCEE0; // CEAA je 0xcee0
            continue :sw 0xCEAC; // falls through
        },
        0xCEAC => {
            m.mark(0xCEAC);
            m.si = m.add(u16, m.si, m.di); // CEAC add si, di
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // CEAE cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xCEAC; // CEB3 je 0xceac
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // CEB5 cmp word ptr [bp - 0xc], si
            if (!m.zf) continue :sw 0xCEE0; // CEB8 jne 0xcee0
            m.wb(m.si +% 0x9EF6, 0x0); // CEBA mov byte ptr [si - 0x610a], 0
            m.bx = m.rw(m.bp +% 0xFFF6); // CEBF mov bx, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.bx +% 0x9EF6), 0x0); // CEC2 cmp byte ptr [bx - 0x610a], 0
            if (m.zf) continue :sw 0xCECC; // CEC7 je 0xcecc
            continue :sw 0xCDFC; // CEC9 jmp 0xcdfc
        },
        0xCECC => {
            m.mark(0xCECC);
            m.push(0x1B); // CECC push 0x1b
            m.push(m.bx); // CECE push bx
            m.far(.see_white, 0xCECF); // CECF lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // CED4 or ax, ax
            if (m.sf != m.of) continue :sw 0xCEDB; // CED6 jl 0xcedb
            continue :sw 0xCE1C; // CED8 jmp 0xce1c
        },
        0xCEDB => {
            m.mark(0xCEDB);
            m.wb(m.si +% 0x9EF6, 0x5); // CEDB mov byte ptr [si - 0x610a], 5
            continue :sw 0xCEE0; // falls through
        },
        0xCEE0 => {
            m.mark(0xCEE0);
            m.setAl(m.rb(0xA051)); // CEE0 mov al, byte ptr [0xa051]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // CEE3 sub ah, ah
            m.di = m.ax; // CEE5 mov di, ax
            m.cmp(u8, m.rb(m.di +% 0x0850), m.ah()); // CEE7 cmp byte ptr [di + 0x850], ah
            if (m.zf) continue :sw 0xCEF0; // CEEB je 0xcef0
            continue :sw 0xCF95; // CEED jmp 0xcf95
        },
        0xCEF0 => {
            m.mark(0xCEF0);
            m.cmp(u16, m.di, 0x48); // CEF0 cmp di, 0x48
            if (m.sf == m.of) continue :sw 0xCEFA; // CEF3 jge 0xcefa
            m.si = 0x48; // CEF5 mov si, 0x48
            continue :sw 0xCEFD; // CEF8 jmp 0xcefd
        },
        0xCEFA => {
            m.mark(0xCEFA);
            m.si = 0x4D; // CEFA mov si, 0x4d
            continue :sw 0xCEFD; // falls through
        },
        0xCEFD => {
            m.mark(0xCEFD);
            m.ww(m.bp +% 0xFFF6, m.si); // CEFD mov word ptr [bp - 0xa], si
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // CF00 cmp byte ptr [si - 0x610a], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xCF11; // CF05 jg 0xcf11
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // CF07 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xCF11; // CF0C je 0xcf11
            continue :sw 0xCF95; // CF0E jmp 0xcf95
        },
        0xCF11 => {
            m.mark(0xCF11);
            m.bx = m.si; // CF11 mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // CF13 sub bx, word ptr [bp - 0xc]
            m.setAl(m.rb(m.bx +% 0x0B66)); // CF16 mov al, byte ptr [bx + 0xb66]
            m.cbw(); // CF1A cbw
            m.di = m.ax; // CF1B mov di, ax
            m.di = m.@"or"(u16, m.di, m.di); // CF1D or di, di
            if (m.zf) continue :sw 0xCF95; // CF1F je 0xcf95
            continue :sw 0xCF21; // falls through
        },
        0xCF21 => {
            m.mark(0xCF21);
            m.si = m.add(u16, m.si, m.di); // CF21 add si, di
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // CF23 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xCF21; // CF28 je 0xcf21
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // CF2A cmp word ptr [bp - 0xc], si
            if (!m.zf) continue :sw 0xCF95; // CF2D jne 0xcf95
            m.wb(m.si +% 0x9EF6, 0x0); // CF2F mov byte ptr [si - 0x610a], 0
            m.bx = m.rw(m.bp +% 0xFFF6); // CF34 mov bx, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.bx +% 0x9EF6), 0x0); // CF37 cmp byte ptr [bx - 0x610a], 0
            if (m.zf) continue :sw 0xCF4E; // CF3C je 0xcf4e
            m.push(0x1B); // CF3E push 0x1b
            m.push(m.bx); // CF40 push bx
            m.far(.see_white, 0xCF41); // CF41 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // CF46 or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xCF90; // CF48 jle 0xcf90
            continue :sw 0xCE1F; // CF4A jmp 0xce1f
        },
        0xCF4E => {
            m.mark(0xCF4E);
            m.push(0x1B); // CF4E push 0x1b
            m.push(m.bx); // CF50 push bx
            m.far(.see_white, 0xCF51); // CF51 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // CF56 or ax, ax
            if (m.sf != m.of) continue :sw 0xCF5D; // CF58 jl 0xcf5d
            continue :sw 0xCE1C; // CF5A jmp 0xce1c
        },
        0xCF5D => {
            m.mark(0xCF5D);
            m.ww(m.bp +% 0xFFF6, m.sub(u16, m.rw(m.bp +% 0xFFF6), m.di)); // CF5D sub word ptr [bp - 0xa], di
            m.bx = m.rw(m.bp +% 0xFFF6); // CF60 mov bx, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.bx +% 0x9EF6), 0x0); // CF63 cmp byte ptr [bx - 0x610a], 0
            if (!m.zf) continue :sw 0xCF7A; // CF68 jne 0xcf7a
            m.push(0x1B); // CF6A push 0x1b
            m.push(m.bx); // CF6C push bx
            m.far(.see_white, 0xCF6D); // CF6D lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // CF72 or ax, ax
            if (m.sf != m.of) continue :sw 0xCF90; // CF74 jl 0xcf90
            continue :sw 0xCE1C; // CF76 jmp 0xce1c
        },
        0xCF7A => {
            m.mark(0xCF7A);
            m.cmp(u8, m.rb(m.bx +% 0x9EF6), 0x7); // CF7A cmp byte ptr [bx - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xCF90; // CF7F jle 0xcf90
            m.push(0x1B); // CF81 push 0x1b
            m.push(m.bx); // CF83 push bx
            m.far(.see_white, 0xCF84); // CF84 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // CF89 or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xCF90; // CF8B jle 0xcf90
            continue :sw 0xCE1F; // CF8D jmp 0xce1f
        },
        0xCF90 => {
            m.mark(0xCF90);
            m.wb(m.si +% 0x9EF6, 0x5); // CF90 mov byte ptr [si - 0x610a], 5
            continue :sw 0xCF95; // falls through
        },
        0xCF95 => {
            m.mark(0xCF95);
            m.setAl(m.rb(0xA051)); // CF95 mov al, byte ptr [0xa051]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // CF98 sub ah, ah
            m.di = m.ax; // CF9A mov di, ax
            m.di = m.add(u16, m.di, 0x13); // CF9C add di, 0x13
            continue :sw 0xDA2E; // CF9F jmp 0xda2e
        },
        0xCFA2 => {
            m.mark(0xCFA2);
            m.ax = m.rw(0xA272); // CFA2 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // CFA5 cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xCFAD; // CFA8 jle 0xcfad
            continue :sw 0xD0A4; // CFAA jmp 0xd0a4
        },
        0xCFAD => {
            m.mark(0xCFAD);
            m.setAl(m.rb(0xA03C)); // CFAD mov al, byte ptr [0xa03c]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // CFB0 sub ah, ah
            m.di = m.ax; // CFB2 mov di, ax
            m.cmp(u8, m.rb(m.di +% 0xA164), 0xC); // CFB4 cmp byte ptr [di - 0x5e9c], 0xc
            if (m.zf or m.sf != m.of) continue :sw 0xCFF0; // CFB9 jle 0xcff0
            m.setAl(m.rb(m.di +% 0xA164)); // CFBB mov al, byte ptr [di - 0x5e9c]
            m.cbw(); // CFBF cbw
            m.bx = m.ax; // CFC0 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // CFC2 mov al, byte ptr [bx + 0x490]
            m.cbw(); // CFC6 cbw
            m.si = m.ax; // CFC7 mov si, ax
            continue :sw 0xCFC9; // falls through
        },
        0xCFC9 => {
            m.mark(0xCFC9);
            m.di = m.add(u16, m.di, m.si); // CFC9 add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // CFCB cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xCFC9; // CFD0 je 0xcfc9
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x4); // CFD2 cmp byte ptr [di - 0x610a], 4
            if (m.sf != m.of) continue :sw 0xCFF0; // CFD7 jl 0xcff0
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x5); // CFD9 cmp byte ptr [di - 0x610a], 5
            if (!m.zf and m.sf == m.of) continue :sw 0xCFF0; // CFDE jg 0xcff0
            continue :sw 0xCFE0; // falls through
        },
        0xCFE0 => {
            m.mark(0xCFE0);
            m.bx = m.rw(m.bp +% 0x000A); // CFE0 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // CFE3 inc byte ptr [bx]
            m.ax = m.rw(m.bp +% 0xFFFE); // CFE5 mov ax, word ptr [bp - 2]
            m.ax = m.add(u16, m.ax, 0x7D0); // CFE8 add ax, 0x7d0
            m.si = m.pop(); // CFEB pop si
            m.di = m.pop(); // CFEC pop di
            m.sp = m.bp;
            m.bp = m.pop(); // CFED leave
            return; // CFEE retf
        },
        0xCFF0 => {
            m.mark(0xCFF0);
            m.setAl(m.rb(0xA03D)); // CFF0 mov al, byte ptr [0xa03d]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // CFF3 sub ah, ah
            m.di = m.ax; // CFF5 mov di, ax
            m.cmp(u8, m.rb(m.di +% 0xA164), 0xC); // CFF7 cmp byte ptr [di - 0x5e9c], 0xc
            if (m.zf or m.sf != m.of) continue :sw 0xD023; // CFFC jle 0xd023
            m.setAl(m.rb(m.di +% 0xA164)); // CFFE mov al, byte ptr [di - 0x5e9c]
            m.cbw(); // D002 cbw
            m.bx = m.ax; // D003 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // D005 mov al, byte ptr [bx + 0x490]
            m.cbw(); // D009 cbw
            m.si = m.ax; // D00A mov si, ax
            continue :sw 0xD00C; // falls through
        },
        0xD00C => {
            m.mark(0xD00C);
            m.di = m.add(u16, m.di, m.si); // D00C add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D00E cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xD00C; // D013 je 0xd00c
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x4); // D015 cmp byte ptr [di - 0x610a], 4
            if (m.sf != m.of) continue :sw 0xD023; // D01A jl 0xd023
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x5); // D01C cmp byte ptr [di - 0x610a], 5
            if (m.zf or m.sf != m.of) continue :sw 0xCFE0; // D021 jle 0xcfe0
            continue :sw 0xD023; // falls through
        },
        0xD023 => {
            m.mark(0xD023);
            m.setAl(m.rb(0xA03E)); // D023 mov al, byte ptr [0xa03e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // D026 sub ah, ah
            m.di = m.ax; // D028 mov di, ax
            m.cmp(u8, m.rb(m.di +% 0xA164), 0x9); // D02A cmp byte ptr [di - 0x5e9c], 9
            if (m.sf != m.of) continue :sw 0xD05D; // D02F jl 0xd05d
            m.cmp(u8, m.rb(m.di +% 0xA164), 0xC); // D031 cmp byte ptr [di - 0x5e9c], 0xc
            if (!m.zf and m.sf == m.of) continue :sw 0xD05D; // D036 jg 0xd05d
            m.setAl(m.rb(m.di +% 0xA164)); // D038 mov al, byte ptr [di - 0x5e9c]
            m.cbw(); // D03C cbw
            m.bx = m.ax; // D03D mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // D03F mov al, byte ptr [bx + 0x490]
            m.cbw(); // D043 cbw
            m.si = m.ax; // D044 mov si, ax
            continue :sw 0xD046; // falls through
        },
        0xD046 => {
            m.mark(0xD046);
            m.di = m.add(u16, m.di, m.si); // D046 add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D048 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xD046; // D04D je 0xd046
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x3); // D04F cmp byte ptr [di - 0x610a], 3
            if (m.zf) continue :sw 0xCFE0; // D054 je 0xcfe0
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x5); // D056 cmp byte ptr [di - 0x610a], 5
            if (m.zf) continue :sw 0xCFE0; // D05B je 0xcfe0
            continue :sw 0xD05D; // falls through
        },
        0xD05D => {
            m.mark(0xD05D);
            m.setAl(m.rb(0xA03F)); // D05D mov al, byte ptr [0xa03f]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // D060 sub ah, ah
            m.di = m.ax; // D062 mov di, ax
            m.cmp(u8, m.rb(m.di +% 0xA164), 0x9); // D064 cmp byte ptr [di - 0x5e9c], 9
            if (m.sf != m.of) continue :sw 0xD09D; // D069 jl 0xd09d
            m.cmp(u8, m.rb(m.di +% 0xA164), 0xC); // D06B cmp byte ptr [di - 0x5e9c], 0xc
            if (!m.zf and m.sf == m.of) continue :sw 0xD09D; // D070 jg 0xd09d
            m.setAl(m.rb(m.di +% 0xA164)); // D072 mov al, byte ptr [di - 0x5e9c]
            m.cbw(); // D076 cbw
            m.bx = m.ax; // D077 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // D079 mov al, byte ptr [bx + 0x490]
            m.cbw(); // D07D cbw
            m.si = m.ax; // D07E mov si, ax
            continue :sw 0xD080; // falls through
        },
        0xD080 => {
            m.mark(0xD080);
            m.di = m.add(u16, m.di, m.si); // D080 add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D082 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xD080; // D087 je 0xd080
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x3); // D089 cmp byte ptr [di - 0x610a], 3
            if (!m.zf) continue :sw 0xD093; // D08E jne 0xd093
            continue :sw 0xCFE0; // D090 jmp 0xcfe0
        },
        0xD093 => {
            m.mark(0xD093);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x5); // D093 cmp byte ptr [di - 0x610a], 5
            if (!m.zf) continue :sw 0xD09D; // D098 jne 0xd09d
            continue :sw 0xCFE0; // D09A jmp 0xcfe0
        },
        0xD09D => {
            m.mark(0xD09D);
            m.setAl(m.rb(0xA051)); // D09D mov al, byte ptr [0xa051]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // D0A0 sub ah, ah
            m.di = m.ax; // D0A2 mov di, ax
            continue :sw 0xD0A4; // falls through
        },
        0xD0A4 => {
            m.mark(0xD0A4);
            m.si = m.rw(m.bp +% 0xFFF4); // D0A4 mov si, word ptr [bp - 0xc]
            m.cmp(u16, m.si, 0x62); // D0A7 cmp si, 0x62
            if (m.zf or m.sf != m.of) continue :sw 0xD0AF; // D0AA jle 0xd0af
            continue :sw 0xD8DE; // D0AC jmp 0xd8de
        },
        0xD0AF => {
            m.mark(0xD0AF);
            m.cmp(u16, m.di, 0x5B); // D0AF cmp di, 0x5b
            if (m.sf != m.of) continue :sw 0xD0B7; // D0B2 jl 0xd0b7
            continue :sw 0xD4C0; // D0B4 jmp 0xd4c0
        },
        0xD0B7 => {
            m.mark(0xD0B7);
            m.cmp(u16, m.di, 0x51); // D0B7 cmp di, 0x51
            if (m.zf) continue :sw 0xD0BF; // D0BA je 0xd0bf
            continue :sw 0xD26C; // D0BC jmp 0xd26c
        },
        0xD0BF => {
            m.mark(0xD0BF);
            m.bx = 0xBB8; // D0BF mov bx, 0xbb8
            m.bx = m.sub(u16, m.bx, m.si); // D0C2 sub bx, si
            m.cmp(u8, m.rb(m.bx), 0x0); // D0C4 cmp byte ptr [bx], 0
            if (m.zf) continue :sw 0xD142; // D0C7 je 0xd142
            m.cmp(u8, m.rb(0x9F48), 0x7); // D0C9 cmp byte ptr [0x9f48], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xD0DA; // D0CE jg 0xd0da
            m.cmp(u8, m.rb(0x9F48), 0x0); // D0D0 cmp byte ptr [0x9f48], 0
            if (m.zf) continue :sw 0xD0DA; // D0D5 je 0xd0da
            continue :sw 0xD271; // D0D7 jmp 0xd271
        },
        0xD0DA => {
            m.mark(0xD0DA);
            m.bx = 0xBB8; // D0DA mov bx, 0xbb8
            m.bx = m.sub(u16, m.bx, m.si); // D0DD sub bx, si
            m.setAl(m.rb(m.bx)); // D0DF mov al, byte ptr [bx]
            m.cbw(); // D0E1 cbw
            m.di = m.ax; // D0E2 mov di, ax
            m.si = m.di +% 0x0052; // D0E4 lea si, [di + 0x52]
            continue :sw 0xD0EC; // D0E7 jmp 0xd0ec
        },
        0xD0EA => {
            m.mark(0xD0EA);
            m.si = m.add(u16, m.si, m.di); // D0EA add si, di
            continue :sw 0xD0EC; // falls through
        },
        0xD0EC => {
            m.mark(0xD0EC);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D0EC cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD0EA; // D0F1 je 0xd0ea
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // D0F3 cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xD0FB; // D0F6 je 0xd0fb
            continue :sw 0xD271; // D0F8 jmp 0xd271
        },
        0xD0FB => {
            m.mark(0xD0FB);
            m.wb(m.si +% 0x9EF6, 0x0); // D0FB mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(0x9F48), 0x0); // D100 cmp byte ptr [0x9f48], 0
            if (!m.zf) continue :sw 0xD174; // D105 jne 0xd174
            m.push(0x1B); // D107 push 0x1b
            m.push(0x52); // D109 push 0x52
            m.far(.see_white, 0xD10B); // D10B lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D110 or ax, ax
            if (m.sf != m.of) continue :sw 0xD117; // D112 jl 0xd117
            continue :sw 0xCE1C; // D114 jmp 0xce1c
        },
        0xD117 => {
            m.mark(0xD117);
            m.cmp(u16, m.di, 0xFFF5); // D117 cmp di, -0xb
            if (!m.zf) continue :sw 0xD13A; // D11A jne 0xd13a
            m.cmp(u8, m.rb(0x9F51), 0x0); // D11C cmp byte ptr [0x9f51], 0
            if (!m.zf) continue :sw 0xD12A; // D121 jne 0xd12a
            m.push(0x1B); // D123 push 0x1b
            m.push(0x5B); // D125 push 0x5b
            continue :sw 0xD25C; // D127 jmp 0xd25c
        },
        0xD12A => {
            m.mark(0xD12A);
            m.push(0x1B); // D12A push 0x1b
            m.push(0x5B); // D12C push 0x5b
            m.far(.see_white, 0xD12E); // D12E lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D133 or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xD13A; // D135 jle 0xd13a
            continue :sw 0xCE1C; // D137 jmp 0xce1c
        },
        0xD13A => {
            m.mark(0xD13A);
            m.wb(m.si +% 0x9EF6, 0x5); // D13A mov byte ptr [si - 0x610a], 5
            continue :sw 0xD271; // D13F jmp 0xd271
        },
        0xD142 => {
            m.mark(0xD142);
            m.cmp(u16, m.si, 0x51); // D142 cmp si, 0x51
            if (m.sf == m.of) continue :sw 0xD14A; // D145 jge 0xd14a
            continue :sw 0xD1E4; // D147 jmp 0xd1e4
        },
        0xD14A => {
            m.mark(0xD14A);
            m.cmp(u16, m.si, 0x58); // D14A cmp si, 0x58
            if (m.zf or m.sf != m.of) continue :sw 0xD152; // D14D jle 0xd152
            continue :sw 0xD271; // D14F jmp 0xd271
        },
        0xD152 => {
            m.mark(0xD152);
            m.cmp(u8, m.rb(0x9F48), 0x7); // D152 cmp byte ptr [0x9f48], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xD15C; // D157 jg 0xd15c
            continue :sw 0xD271; // D159 jmp 0xd271
        },
        0xD15C => {
            m.mark(0xD15C);
            m.si = 0x53; // D15C mov si, 0x53
            continue :sw 0xD163; // D15F jmp 0xd163
        },
        0xD162 => {
            m.mark(0xD162);
            m.si = m.inc(u16, m.si); // D162 inc si
            continue :sw 0xD163; // falls through
        },
        0xD163 => {
            m.mark(0xD163);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D163 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD162; // D168 je 0xd162
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // D16A cmp word ptr [bp - 0xc], si
            if (!m.zf) continue :sw 0xD18A; // D16D jne 0xd18a
            m.wb(m.si +% 0x9EF6, 0x0); // D16F mov byte ptr [si - 0x610a], 0
            continue :sw 0xD174; // falls through
        },
        0xD174 => {
            m.mark(0xD174);
            m.push(0x1B); // D174 push 0x1b
            m.push(0x52); // D176 push 0x52
            m.far(.see_white, 0xD178); // D178 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D17D or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xD13A; // D17F jle 0xd13a
            m.cmp(u8, m.rb(0x9F48), 0x8); // D181 cmp byte ptr [0x9f48], 8
            continue :sw 0xD898; // D186 jmp 0xd898
        },
        0xD18A => {
            m.mark(0xD18A);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x4); // D18A cmp byte ptr [si - 0x610a], 4
            if (m.zf) continue :sw 0xD194; // D18F je 0xd194
            continue :sw 0xD271; // D191 jmp 0xd271
        },
        0xD194 => {
            m.mark(0xD194);
            m.wb(m.si +% 0x9EF6, 0x0); // D194 mov byte ptr [si - 0x610a], 0
            m.push(0xF); // D199 push 0xf
            m.push(0x52); // D19B push 0x52
            m.far(.see_white, 0xD19D); // D19D lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D1A2 or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xD1DC; // D1A4 jle 0xd1dc
            continue :sw 0xD1A6; // falls through
        },
        0xD1A6 => {
            m.mark(0xD1A6);
            m.wb(m.si +% 0x9EF6, 0x4); // D1A6 mov byte ptr [si - 0x610a], 4
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // D1AB inc word ptr [bp - 8]
            m.ax = m.rw(0x9356); // D1AE mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // D1B1 cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xD1B9; // D1B4 jl 0xd1b9
            continue :sw 0xDAE4; // D1B6 jmp 0xdae4
        },
        0xD1B9 => {
            m.mark(0xD1B9);
            m.ax = m.rw(0xA272); // D1B9 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // D1BC cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xD1C4; // D1BF jg 0xd1c4
            continue :sw 0xDB15; // D1C1 jmp 0xdb15
        },
        0xD1C4 => {
            m.mark(0xD1C4);
            m.cmp(u16, m.rw(m.bp +% 0x0008), 0x0); // D1C4 cmp word ptr [bp + 8], 0
            if (m.zf) continue :sw 0xD1CD; // D1C8 je 0xd1cd
            continue :sw 0xDB15; // D1CA jmp 0xdb15
        },
        0xD1CD => {
            m.mark(0xD1CD);
            m.cmp(u16, m.rw(0xAE38), 0xED8); // D1CD cmp word ptr [0xae38], 0xed8
            if (m.zf or m.sf != m.of) continue :sw 0xD1D8; // D1D3 jle 0xd1d8
            continue :sw 0xDAE4; // D1D5 jmp 0xdae4
        },
        0xD1D8 => {
            m.mark(0xD1D8);
            continue :sw 0xDB15; // D1D8 jmp 0xdb15
        },
        0xD1DC => {
            m.mark(0xD1DC);
            m.wb(m.si +% 0x9EF6, 0x4); // D1DC mov byte ptr [si - 0x610a], 4
            continue :sw 0xD271; // D1E1 jmp 0xd271
        },
        0xD1E4 => {
            m.mark(0xD1E4);
            m.cmp(u8, m.rb(m.si +% 0x100A), 0x1); // D1E4 cmp byte ptr [si + 0x100a], 1
            if (!m.zf) continue :sw 0xD222; // D1E9 jne 0xd222
            m.cmp(u8, m.rb(0x9F3D), 0x7); // D1EB cmp byte ptr [0x9f3d], 7
            if (m.zf or m.sf != m.of) continue :sw 0xD271; // D1F0 jle 0xd271
            m.si = 0x47; // D1F2 mov si, 0x47
            continue :sw 0xD1F5; // falls through
        },
        0xD1F5 => {
            m.mark(0xD1F5);
            m.si = m.sub(u16, m.si, 0xA); // D1F5 sub si, 0xa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D1F8 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD1F5; // D1FD je 0xd1f5
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // D1FF cmp word ptr [bp - 0xc], si
            if (!m.zf) continue :sw 0xD271; // D202 jne 0xd271
            m.wb(m.si +% 0x9EF6, 0x0); // D204 mov byte ptr [si - 0x610a], 0
            m.push(0x1B); // D209 push 0x1b
            m.push(0x47); // D20B push 0x47
            m.far(.see_white, 0xD20D); // D20D lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D212 or ax, ax
            if (!m.zf and m.sf == m.of) continue :sw 0xD219; // D214 jg 0xd219
            continue :sw 0xD13A; // D216 jmp 0xd13a
        },
        0xD219 => {
            m.mark(0xD219);
            m.cmp(u8, m.rb(0x9F3D), 0x8); // D219 cmp byte ptr [0x9f3d], 8
            continue :sw 0xD898; // D21E jmp 0xd898
        },
        0xD222 => {
            m.mark(0xD222);
            m.cmp(u8, m.rb(m.si +% 0x100A), 0x2); // D222 cmp byte ptr [si + 0x100a], 2
            if (!m.zf) continue :sw 0xD271; // D227 jne 0xd271
            m.cmp(u8, m.rb(0x9F48), 0x0); // D229 cmp byte ptr [0x9f48], 0
            if (m.zf) continue :sw 0xD237; // D22E je 0xd237
            m.cmp(u8, m.rb(0x9F48), 0x7); // D230 cmp byte ptr [0x9f48], 7
            if (m.zf or m.sf != m.of) continue :sw 0xD271; // D235 jle 0xd271
            continue :sw 0xD237; // falls through
        },
        0xD237 => {
            m.mark(0xD237);
            m.si = 0x52; // D237 mov si, 0x52
            continue :sw 0xD23A; // falls through
        },
        0xD23A => {
            m.mark(0xD23A);
            m.si = m.sub(u16, m.si, 0xA); // D23A sub si, 0xa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D23D cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD23A; // D242 je 0xd23a
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // D244 cmp word ptr [bp - 0xc], si
            if (!m.zf) continue :sw 0xD271; // D247 jne 0xd271
            m.wb(m.si +% 0x9EF6, 0x0); // D249 mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(0x9F48), 0x0); // D24E cmp byte ptr [0x9f48], 0
            if (m.zf) continue :sw 0xD258; // D253 je 0xd258
            continue :sw 0xD174; // D255 jmp 0xd174
        },
        0xD258 => {
            m.mark(0xD258);
            m.push(0x1B); // D258 push 0x1b
            m.push(0x52); // D25A push 0x52
            continue :sw 0xD25C; // falls through
        },
        0xD25C => {
            m.mark(0xD25C);
            m.far(.see_white, 0xD25C); // D25C lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D261 or ax, ax
            if (m.sf == m.of) continue :sw 0xD268; // D263 jge 0xd268
            continue :sw 0xD13A; // D265 jmp 0xd13a
        },
        0xD268 => {
            m.mark(0xD268);
            continue :sw 0xCE1C; // D268 jmp 0xce1c
        },
        0xD26C => {
            m.mark(0xD26C);
            m.cmp(u16, m.di, 0x52); // D26C cmp di, 0x52
            if (!m.zf) continue :sw 0xD2CE; // D26F jne 0xd2ce
            continue :sw 0xD271; // falls through
        },
        0xD271 => {
            m.mark(0xD271);
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), 0x5D); // D271 cmp word ptr [bp - 0xc], 0x5d
            if (m.sf == m.of) continue :sw 0xD27A; // D275 jge 0xd27a
            continue :sw 0xD8D7; // D277 jmp 0xd8d7
        },
        0xD27A => {
            m.mark(0xD27A);
            m.di = 0x5C; // D27A mov di, 0x5c
            m.cmp(u8, m.rb(0x9F52), 0x0); // D27D cmp byte ptr [0x9f52], 0
            if (!m.zf) continue :sw 0xD2B2; // D282 jne 0xd2b2
            m.si = 0x5D; // D284 mov si, 0x5d
            continue :sw 0xD28B; // D287 jmp 0xd28b
        },
        0xD28A => {
            m.mark(0xD28A);
            m.si = m.inc(u16, m.si); // D28A inc si
            continue :sw 0xD28B; // falls through
        },
        0xD28B => {
            m.mark(0xD28B);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D28B cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD28A; // D290 je 0xd28a
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // D292 cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xD29A; // D295 je 0xd29a
            continue :sw 0xD8D7; // D297 jmp 0xd8d7
        },
        0xD29A => {
            m.mark(0xD29A);
            m.wb(m.si +% 0x9EF6, 0x0); // D29A mov byte ptr [si - 0x610a], 0
            m.push(0x1B); // D29F push 0x1b
            m.push(m.di); // D2A1 push di
            m.far(.see_white, 0xD2A2); // D2A2 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D2A7 or ax, ax
            if (m.sf != m.of) continue :sw 0xD2AE; // D2A9 jl 0xd2ae
            continue :sw 0xCE1C; // D2AB jmp 0xce1c
        },
        0xD2AE => {
            m.mark(0xD2AE);
            m.di = m.dec(u16, m.di); // D2AE dec di
            continue :sw 0xD82E; // D2AF jmp 0xd82e
        },
        0xD2B2 => {
            m.mark(0xD2B2);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // D2B2 cmp byte ptr [di - 0x610a], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xD2BC; // D2B7 jg 0xd2bc
            continue :sw 0xD8D7; // D2B9 jmp 0xd8d7
        },
        0xD2BC => {
            m.mark(0xD2BC);
            m.si = 0x5D; // D2BC mov si, 0x5d
            continue :sw 0xD2C3; // D2BF jmp 0xd2c3
        },
        0xD2C2 => {
            m.mark(0xD2C2);
            m.si = m.inc(u16, m.si); // D2C2 inc si
            continue :sw 0xD2C3; // falls through
        },
        0xD2C3 => {
            m.mark(0xD2C3);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D2C3 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD2C2; // D2C8 je 0xd2c2
            continue :sw 0xD4B0; // D2CA jmp 0xd4b0
        },
        0xD2CE => {
            m.mark(0xD2CE);
            m.cmp(u16, m.di, 0x58); // D2CE cmp di, 0x58
            if (m.zf) continue :sw 0xD2D6; // D2D1 je 0xd2d6
            continue :sw 0xD450; // D2D3 jmp 0xd450
        },
        0xD2D6 => {
            m.mark(0xD2D6);
            m.bx = 0xBBD; // D2D6 mov bx, 0xbbd
            m.bx = m.sub(u16, m.bx, m.si); // D2D9 sub bx, si
            m.cmp(u8, m.rb(m.bx), 0x0); // D2DB cmp byte ptr [bx], 0
            if (m.zf) continue :sw 0xD358; // D2DE je 0xd358
            m.cmp(u8, m.rb(0x9F4D), 0x7); // D2E0 cmp byte ptr [0x9f4d], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xD2F1; // D2E5 jg 0xd2f1
            m.cmp(u8, m.rb(0x9F4D), 0x0); // D2E7 cmp byte ptr [0x9f4d], 0
            if (m.zf) continue :sw 0xD2F1; // D2EC je 0xd2f1
            continue :sw 0xD458; // D2EE jmp 0xd458
        },
        0xD2F1 => {
            m.mark(0xD2F1);
            m.bx = 0xBBD; // D2F1 mov bx, 0xbbd
            m.bx = m.sub(u16, m.bx, m.si); // D2F4 sub bx, si
            m.setAl(m.rb(m.bx)); // D2F6 mov al, byte ptr [bx]
            m.cbw(); // D2F8 cbw
            m.di = m.ax; // D2F9 mov di, ax
            m.si = m.di +% 0x0057; // D2FB lea si, [di + 0x57]
            continue :sw 0xD302; // D2FE jmp 0xd302
        },
        0xD300 => {
            m.mark(0xD300);
            m.si = m.add(u16, m.si, m.di); // D300 add si, di
            continue :sw 0xD302; // falls through
        },
        0xD302 => {
            m.mark(0xD302);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D302 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD300; // D307 je 0xd300
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // D309 cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xD311; // D30C je 0xd311
            continue :sw 0xD458; // D30E jmp 0xd458
        },
        0xD311 => {
            m.mark(0xD311);
            m.wb(m.si +% 0x9EF6, 0x0); // D311 mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(0x9F4D), 0x0); // D316 cmp byte ptr [0x9f4d], 0
            if (!m.zf) continue :sw 0xD386; // D31B jne 0xd386
            m.push(0x1B); // D31D push 0x1b
            m.push(0x57); // D31F push 0x57
            m.far(.see_white, 0xD321); // D321 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D326 or ax, ax
            if (m.sf != m.of) continue :sw 0xD32D; // D328 jl 0xd32d
            continue :sw 0xCE1C; // D32A jmp 0xce1c
        },
        0xD32D => {
            m.mark(0xD32D);
            m.cmp(u16, m.di, 0xFFF7); // D32D cmp di, -9
            if (!m.zf) continue :sw 0xD350; // D330 jne 0xd350
            m.cmp(u8, m.rb(0x9F58), 0x0); // D332 cmp byte ptr [0x9f58], 0
            if (!m.zf) continue :sw 0xD340; // D337 jne 0xd340
            m.push(0x1B); // D339 push 0x1b
            m.push(0x62); // D33B push 0x62
            continue :sw 0xD440; // D33D jmp 0xd440
        },
        0xD340 => {
            m.mark(0xD340);
            m.push(0x1B); // D340 push 0x1b
            m.push(0x62); // D342 push 0x62
            m.far(.see_white, 0xD344); // D344 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D349 or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xD350; // D34B jle 0xd350
            continue :sw 0xCE1C; // D34D jmp 0xce1c
        },
        0xD350 => {
            m.mark(0xD350);
            m.wb(m.si +% 0x9EF6, 0x5); // D350 mov byte ptr [si - 0x610a], 5
            continue :sw 0xD458; // D355 jmp 0xd458
        },
        0xD358 => {
            m.mark(0xD358);
            m.cmp(u16, m.si, 0x51); // D358 cmp si, 0x51
            if (m.sf != m.of) continue :sw 0xD3C4; // D35B jl 0xd3c4
            m.cmp(u16, m.si, 0x58); // D35D cmp si, 0x58
            if (m.zf or m.sf != m.of) continue :sw 0xD365; // D360 jle 0xd365
            continue :sw 0xD458; // D362 jmp 0xd458
        },
        0xD365 => {
            m.mark(0xD365);
            m.cmp(u8, m.rb(0x9F4D), 0x7); // D365 cmp byte ptr [0x9f4d], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xD36F; // D36A jg 0xd36f
            continue :sw 0xD458; // D36C jmp 0xd458
        },
        0xD36F => {
            m.mark(0xD36F);
            m.si = 0x56; // D36F mov si, 0x56
            continue :sw 0xD375; // D372 jmp 0xd375
        },
        0xD374 => {
            m.mark(0xD374);
            m.si = m.dec(u16, m.si); // D374 dec si
            continue :sw 0xD375; // falls through
        },
        0xD375 => {
            m.mark(0xD375);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D375 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD374; // D37A je 0xd374
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // D37C cmp word ptr [bp - 0xc], si
            if (!m.zf) continue :sw 0xD39C; // D37F jne 0xd39c
            m.wb(m.si +% 0x9EF6, 0x0); // D381 mov byte ptr [si - 0x610a], 0
            continue :sw 0xD386; // falls through
        },
        0xD386 => {
            m.mark(0xD386);
            m.push(0x1B); // D386 push 0x1b
            m.push(0x57); // D388 push 0x57
            m.far(.see_white, 0xD38A); // D38A lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D38F or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xD350; // D391 jle 0xd350
            m.cmp(u8, m.rb(0x9F4D), 0x8); // D393 cmp byte ptr [0x9f4d], 8
            continue :sw 0xD898; // D398 jmp 0xd898
        },
        0xD39C => {
            m.mark(0xD39C);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x4); // D39C cmp byte ptr [si - 0x610a], 4
            if (m.zf) continue :sw 0xD3A6; // D3A1 je 0xd3a6
            continue :sw 0xD458; // D3A3 jmp 0xd458
        },
        0xD3A6 => {
            m.mark(0xD3A6);
            m.wb(m.si +% 0x9EF6, 0x0); // D3A6 mov byte ptr [si - 0x610a], 0
            m.push(0xF); // D3AB push 0xf
            m.push(0x57); // D3AD push 0x57
            m.far(.see_white, 0xD3AF); // D3AF lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D3B4 or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xD3BB; // D3B6 jle 0xd3bb
            continue :sw 0xD1A6; // D3B8 jmp 0xd1a6
        },
        0xD3BB => {
            m.mark(0xD3BB);
            m.wb(m.si +% 0x9EF6, 0x4); // D3BB mov byte ptr [si - 0x610a], 4
            continue :sw 0xD458; // D3C0 jmp 0xd458
        },
        0xD3C4 => {
            m.mark(0xD3C4);
            m.cmp(u8, m.rb(m.si +% 0x100A), 0x8); // D3C4 cmp byte ptr [si + 0x100a], 8
            if (!m.zf) continue :sw 0xD406; // D3C9 jne 0xd406
            m.cmp(u8, m.rb(0x9F44), 0x7); // D3CB cmp byte ptr [0x9f44], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xD3D5; // D3D0 jg 0xd3d5
            continue :sw 0xD458; // D3D2 jmp 0xd458
        },
        0xD3D5 => {
            m.mark(0xD3D5);
            m.si = 0x4E; // D3D5 mov si, 0x4e
            continue :sw 0xD3D8; // falls through
        },
        0xD3D8 => {
            m.mark(0xD3D8);
            m.si = m.sub(u16, m.si, 0xA); // D3D8 sub si, 0xa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D3DB cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD3D8; // D3E0 je 0xd3d8
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // D3E2 cmp word ptr [bp - 0xc], si
            if (!m.zf) continue :sw 0xD458; // D3E5 jne 0xd458
            m.wb(m.si +% 0x9EF6, 0x0); // D3E7 mov byte ptr [si - 0x610a], 0
            m.push(0x1B); // D3EC push 0x1b
            m.push(0x4E); // D3EE push 0x4e
            m.far(.see_white, 0xD3F0); // D3F0 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D3F5 or ax, ax
            if (!m.zf and m.sf == m.of) continue :sw 0xD3FC; // D3F7 jg 0xd3fc
            continue :sw 0xD350; // D3F9 jmp 0xd350
        },
        0xD3FC => {
            m.mark(0xD3FC);
            m.cmp(u8, m.rb(0x9F44), 0x8); // D3FC cmp byte ptr [0x9f44], 8
            continue :sw 0xD898; // D401 jmp 0xd898
        },
        0xD406 => {
            m.mark(0xD406);
            m.cmp(u8, m.rb(m.si +% 0x100A), 0x7); // D406 cmp byte ptr [si + 0x100a], 7
            if (!m.zf) continue :sw 0xD458; // D40B jne 0xd458
            m.cmp(u8, m.rb(0x9F4D), 0x0); // D40D cmp byte ptr [0x9f4d], 0
            if (m.zf) continue :sw 0xD41B; // D412 je 0xd41b
            m.cmp(u8, m.rb(0x9F4D), 0x7); // D414 cmp byte ptr [0x9f4d], 7
            if (m.zf or m.sf != m.of) continue :sw 0xD458; // D419 jle 0xd458
            continue :sw 0xD41B; // falls through
        },
        0xD41B => {
            m.mark(0xD41B);
            m.si = 0x57; // D41B mov si, 0x57
            continue :sw 0xD41E; // falls through
        },
        0xD41E => {
            m.mark(0xD41E);
            m.si = m.sub(u16, m.si, 0xA); // D41E sub si, 0xa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D421 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD41E; // D426 je 0xd41e
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // D428 cmp word ptr [bp - 0xc], si
            if (!m.zf) continue :sw 0xD458; // D42B jne 0xd458
            m.wb(m.si +% 0x9EF6, 0x0); // D42D mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(0x9F4D), 0x0); // D432 cmp byte ptr [0x9f4d], 0
            if (m.zf) continue :sw 0xD43C; // D437 je 0xd43c
            continue :sw 0xD386; // D439 jmp 0xd386
        },
        0xD43C => {
            m.mark(0xD43C);
            m.push(0x1B); // D43C push 0x1b
            m.push(0x57); // D43E push 0x57
            continue :sw 0xD440; // falls through
        },
        0xD440 => {
            m.mark(0xD440);
            m.far(.see_white, 0xD440); // D440 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D445 or ax, ax
            if (m.sf == m.of) continue :sw 0xD44C; // D447 jge 0xd44c
            continue :sw 0xD350; // D449 jmp 0xd350
        },
        0xD44C => {
            m.mark(0xD44C);
            continue :sw 0xCE1C; // D44C jmp 0xce1c
        },
        0xD450 => {
            m.mark(0xD450);
            m.cmp(u16, m.di, 0x57); // D450 cmp di, 0x57
            if (m.zf) continue :sw 0xD458; // D453 je 0xd458
            continue :sw 0xD8D7; // D455 jmp 0xd8d7
        },
        0xD458 => {
            m.mark(0xD458);
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), 0x5B); // D458 cmp word ptr [bp - 0xc], 0x5b
            if (m.sf == m.of) continue :sw 0xD461; // D45C jge 0xd461
            continue :sw 0xD8D7; // D45E jmp 0xd8d7
        },
        0xD461 => {
            m.mark(0xD461);
            m.di = 0x61; // D461 mov di, 0x61
            m.cmp(u8, m.rb(0x9F57), 0x0); // D464 cmp byte ptr [0x9f57], 0
            if (!m.zf) continue :sw 0xD498; // D469 jne 0xd498
            m.si = 0x60; // D46B mov si, 0x60
            continue :sw 0xD471; // D46E jmp 0xd471
        },
        0xD470 => {
            m.mark(0xD470);
            m.si = m.dec(u16, m.si); // D470 dec si
            continue :sw 0xD471; // falls through
        },
        0xD471 => {
            m.mark(0xD471);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D471 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD470; // D476 je 0xd470
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // D478 cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xD480; // D47B je 0xd480
            continue :sw 0xD8D7; // D47D jmp 0xd8d7
        },
        0xD480 => {
            m.mark(0xD480);
            m.wb(m.si +% 0x9EF6, 0x0); // D480 mov byte ptr [si - 0x610a], 0
            m.push(0x1B); // D485 push 0x1b
            m.push(m.di); // D487 push di
            m.far(.see_white, 0xD488); // D488 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D48D or ax, ax
            if (m.sf != m.of) continue :sw 0xD494; // D48F jl 0xd494
            continue :sw 0xCE1C; // D491 jmp 0xce1c
        },
        0xD494 => {
            m.mark(0xD494);
            m.di = m.inc(u16, m.di); // D494 inc di
            continue :sw 0xD82E; // D495 jmp 0xd82e
        },
        0xD498 => {
            m.mark(0xD498);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // D498 cmp byte ptr [di - 0x610a], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xD4A2; // D49D jg 0xd4a2
            continue :sw 0xD8D7; // D49F jmp 0xd8d7
        },
        0xD4A2 => {
            m.mark(0xD4A2);
            m.si = 0x60; // D4A2 mov si, 0x60
            continue :sw 0xD4A9; // D4A5 jmp 0xd4a9
        },
        0xD4A8 => {
            m.mark(0xD4A8);
            m.si = m.dec(u16, m.si); // D4A8 dec si
            continue :sw 0xD4A9; // falls through
        },
        0xD4A9 => {
            m.mark(0xD4A9);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D4A9 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD4A8; // D4AE je 0xd4a8
            continue :sw 0xD4B0; // falls through
        },
        0xD4B0 => {
            m.mark(0xD4B0);
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // D4B0 cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xD4B8; // D4B3 je 0xd4b8
            continue :sw 0xD8D7; // D4B5 jmp 0xd8d7
        },
        0xD4B8 => {
            m.mark(0xD4B8);
            m.wb(m.si +% 0x9EF6, 0x0); // D4B8 mov byte ptr [si - 0x610a], 0
            continue :sw 0xD8C3; // D4BD jmp 0xd8c3
        },
        0xD4C0 => {
            m.mark(0xD4C0);
            m.cmp(u16, m.di, 0x60); // D4C0 cmp di, 0x60
            if (m.sf != m.of) continue :sw 0xD4E2; // D4C3 jl 0xd4e2
            m.cmp(u8, m.rb(0xA573), 0x0); // D4C5 cmp byte ptr [0xa573], 0
            if (m.zf) continue :sw 0xD4D3; // D4CA je 0xd4d3
            m.cmp(u8, m.rb(0x9F4D), 0x8); // D4CC cmp byte ptr [0x9f4d], 8
            if (m.zf) continue :sw 0xD503; // D4D1 je 0xd503
            continue :sw 0xD4D3; // falls through
        },
        0xD4D3 => {
            m.mark(0xD4D3);
            m.cmp(u8, m.rb(0xA574), 0x0); // D4D3 cmp byte ptr [0xa574], 0
            if (m.zf) continue :sw 0xD519; // D4D8 je 0xd519
            m.cmp(u8, m.rb(0x9F4E), 0x8); // D4DA cmp byte ptr [0x9f4e], 8
            continue :sw 0xD501; // D4DF jmp 0xd501
        },
        0xD4E2 => {
            m.mark(0xD4E2);
            m.cmp(u16, m.di, 0x5D); // D4E2 cmp di, 0x5d
            if (!m.zf and m.sf == m.of) continue :sw 0xD519; // D4E5 jg 0xd519
            m.cmp(u8, m.rb(0xA56E), 0x0); // D4E7 cmp byte ptr [0xa56e], 0
            if (m.zf) continue :sw 0xD4F5; // D4EC je 0xd4f5
            m.cmp(u8, m.rb(0x9F48), 0x8); // D4EE cmp byte ptr [0x9f48], 8
            if (m.zf) continue :sw 0xD503; // D4F3 je 0xd503
            continue :sw 0xD4F5; // falls through
        },
        0xD4F5 => {
            m.mark(0xD4F5);
            m.cmp(u8, m.rb(0xA56D), 0x0); // D4F5 cmp byte ptr [0xa56d], 0
            if (m.zf) continue :sw 0xD519; // D4FA je 0xd519
            m.cmp(u8, m.rb(0x9F47), 0x8); // D4FC cmp byte ptr [0x9f47], 8
            continue :sw 0xD501; // falls through
        },
        0xD501 => {
            m.mark(0xD501);
            if (!m.zf) continue :sw 0xD519; // D501 jne 0xd519
            continue :sw 0xD503; // falls through
        },
        0xD503 => {
            m.mark(0xD503);
            m.ax = m.rw(0xA272); // D503 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // D506 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xD515; // D509 jg 0xd515
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x12C)); // D50B add word ptr [bp - 2], 0x12c
            m.bx = m.rw(m.bp +% 0x000A); // D510 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // D513 inc byte ptr [bx]
            continue :sw 0xD515; // falls through
        },
        0xD515 => {
            m.mark(0xD515);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x18)); // D515 add word ptr [bp - 4], 0x18
            continue :sw 0xD519; // falls through
        },
        0xD519 => {
            m.mark(0xD519);
            m.cmp(u16, m.si, 0x51); // D519 cmp si, 0x51
            if (m.sf == m.of) continue :sw 0xD521; // D51C jge 0xd521
            continue :sw 0xD632; // D51E jmp 0xd632
        },
        0xD521 => {
            m.mark(0xD521);
            m.cmp(u16, m.si, 0x58); // D521 cmp si, 0x58
            if (m.zf or m.sf != m.of) continue :sw 0xD529; // D524 jle 0xd529
            continue :sw 0xD632; // D526 jmp 0xd632
        },
        0xD529 => {
            m.mark(0xD529);
            m.di = m.sub(u16, m.di, 0xB); // D529 sub di, 0xb
            m.cmp(u16, m.di, m.si); // D52C cmp di, si
            if (m.zf or m.sf != m.of) continue :sw 0xD5AC; // D52E jle 0xd5ac
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D530 cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xD590; // D535 jne 0xd590
            m.si = m.di +% 0xFFFF; // D537 lea si, [di - 1]
            continue :sw 0xD53D; // D53A jmp 0xd53d
        },
        0xD53C => {
            m.mark(0xD53C);
            m.si = m.dec(u16, m.si); // D53C dec si
            continue :sw 0xD53D; // falls through
        },
        0xD53D => {
            m.mark(0xD53D);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D53D cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD53C; // D542 je 0xd53c
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // D544 cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xD54C; // D547 je 0xd54c
            continue :sw 0xD8D7; // D549 jmp 0xd8d7
        },
        0xD54C => {
            m.mark(0xD54C);
            m.wb(m.si +% 0x9EF6, 0x0); // D54C mov byte ptr [si - 0x610a], 0
            m.push(0x1B); // D551 push 0x1b
            m.push(m.di); // D553 push di
            m.far(.see_white, 0xD554); // D554 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D559 or ax, ax
            if (m.sf != m.of) continue :sw 0xD560; // D55B jl 0xd560
            continue :sw 0xCE1C; // D55D jmp 0xce1c
        },
        0xD560 => {
            m.mark(0xD560);
            m.di = m.inc(u16, m.di); // D560 inc di
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D561 cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xD582; // D566 jne 0xd582
            m.push(0x1B); // D568 push 0x1b
            m.push(m.di); // D56A push di
            m.far(.see_white, 0xD56B); // D56B lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D570 or ax, ax
            if (m.sf != m.of) continue :sw 0xD577; // D572 jl 0xd577
            continue :sw 0xCE1C; // D574 jmp 0xce1c
        },
        0xD577 => {
            m.mark(0xD577);
            m.di = m.inc(u16, m.di); // D577 inc di
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D578 cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xD582; // D57D jne 0xd582
            continue :sw 0xD838; // D57F jmp 0xd838
        },
        0xD582 => {
            m.mark(0xD582);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // D582 cmp byte ptr [di - 0x610a], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xD58C; // D587 jg 0xd58c
            continue :sw 0xD8D2; // D589 jmp 0xd8d2
        },
        0xD58C => {
            m.mark(0xD58C);
            continue :sw 0xD887; // D58C jmp 0xd887
        },
        0xD590 => {
            m.mark(0xD590);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // D590 cmp byte ptr [di - 0x610a], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xD59A; // D595 jg 0xd59a
            continue :sw 0xD8D7; // D597 jmp 0xd8d7
        },
        0xD59A => {
            m.mark(0xD59A);
            m.si = m.di +% 0xFFFF; // D59A lea si, [di - 1]
            continue :sw 0xD5A1; // D59D jmp 0xd5a1
        },
        0xD5A0 => {
            m.mark(0xD5A0);
            m.si = m.dec(u16, m.si); // D5A0 dec si
            continue :sw 0xD5A1; // falls through
        },
        0xD5A1 => {
            m.mark(0xD5A1);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D5A1 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD5A0; // D5A6 je 0xd5a0
            continue :sw 0xD710; // D5A8 jmp 0xd710
        },
        0xD5AC => {
            m.mark(0xD5AC);
            m.di = m.add(u16, m.di, 0x2); // D5AC add di, 2
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D5AF cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xD5FE; // D5B4 jne 0xd5fe
            m.si = m.di; // D5B6 mov si, di
            continue :sw 0xD5B8; // falls through
        },
        0xD5B8 => {
            m.mark(0xD5B8);
            m.si = m.inc(u16, m.si); // D5B8 inc si
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D5B9 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD5B8; // D5BE je 0xd5b8
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // D5C0 cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xD5C8; // D5C3 je 0xd5c8
            continue :sw 0xD8D7; // D5C5 jmp 0xd8d7
        },
        0xD5C8 => {
            m.mark(0xD5C8);
            m.wb(m.si +% 0x9EF6, 0x0); // D5C8 mov byte ptr [si - 0x610a], 0
            m.push(0x1B); // D5CD push 0x1b
            m.push(m.di); // D5CF push di
            m.far(.see_white, 0xD5D0); // D5D0 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D5D5 or ax, ax
            if (m.sf != m.of) continue :sw 0xD5DC; // D5D7 jl 0xd5dc
            continue :sw 0xCE1C; // D5D9 jmp 0xce1c
        },
        0xD5DC => {
            m.mark(0xD5DC);
            m.di = m.dec(u16, m.di); // D5DC dec di
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D5DD cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xD582; // D5E2 jne 0xd582
            m.push(0x1B); // D5E4 push 0x1b
            m.push(m.di); // D5E6 push di
            m.far(.see_white, 0xD5E7); // D5E7 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D5EC or ax, ax
            if (m.sf != m.of) continue :sw 0xD5F3; // D5EE jl 0xd5f3
            continue :sw 0xCE1C; // D5F0 jmp 0xce1c
        },
        0xD5F3 => {
            m.mark(0xD5F3);
            m.di = m.dec(u16, m.di); // D5F3 dec di
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D5F4 cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xD582; // D5F9 jne 0xd582
            continue :sw 0xD838; // D5FB jmp 0xd838
        },
        0xD5FE => {
            m.mark(0xD5FE);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // D5FE cmp byte ptr [di - 0x610a], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xD608; // D603 jg 0xd608
            continue :sw 0xD8D7; // D605 jmp 0xd8d7
        },
        0xD608 => {
            m.mark(0xD608);
            m.si = m.di; // D608 mov si, di
            continue :sw 0xD60A; // falls through
        },
        0xD60A => {
            m.mark(0xD60A);
            m.si = m.inc(u16, m.si); // D60A inc si
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D60B cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD60A; // D610 je 0xd60a
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // D612 cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xD61A; // D615 je 0xd61a
            continue :sw 0xD8D7; // D617 jmp 0xd8d7
        },
        0xD61A => {
            m.mark(0xD61A);
            m.wb(m.si +% 0x9EF6, 0x0); // D61A mov byte ptr [si - 0x610a], 0
            m.push(0x1B); // D61F push 0x1b
            m.push(m.di); // D621 push di
            m.far(.see_white, 0xD622); // D622 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D627 or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xD62E; // D629 jle 0xd62e
            continue :sw 0xD893; // D62B jmp 0xd893
        },
        0xD62E => {
            m.mark(0xD62E);
            continue :sw 0xD8D2; // D62E jmp 0xd8d2
        },
        0xD632 => {
            m.mark(0xD632);
            m.ax = 0xB0; // D632 mov ax, 0xb0
            m.ax = m.sub(u16, m.ax, m.si); // D635 sub ax, si
            m.si = m.ax; // D637 mov si, ax
            m.bx = m.ax; // D639 mov bx, ax
            m.di = m.sub(u16, m.di, 0xA); // D63B sub di, 0xa
            m.bx = m.add(u16, m.bx, m.di); // D63E add bx, di
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), 0x0); // D640 cmp byte ptr [bx + 0xab6], 0
            if (!m.zf) continue :sw 0xD64A; // D645 jne 0xd64a
            continue :sw 0xD720; // D647 jmp 0xd720
        },
        0xD64A => {
            m.mark(0xD64A);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // D64A cmp byte ptr [di - 0x610a], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xD65B; // D64F jg 0xd65b
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D651 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xD65B; // D656 je 0xd65b
            continue :sw 0xD720; // D658 jmp 0xd720
        },
        0xD65B => {
            m.mark(0xD65B);
            m.bx = m.di; // D65B mov bx, di
            m.bx = m.add(u16, m.bx, m.si); // D65D add bx, si
            m.setAl(m.rb(m.bx +% 0x0AB6)); // D65F mov al, byte ptr [bx + 0xab6]
            m.cbw(); // D663 cbw
            m.si = m.ax; // D664 mov si, ax
            continue :sw 0xD666; // falls through
        },
        0xD666 => {
            m.mark(0xD666);
            m.di = m.add(u16, m.di, m.si); // D666 add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D668 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xD666; // D66D je 0xd666
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.di); // D66F cmp word ptr [bp - 0xc], di
            if (!m.zf) continue :sw 0xD6D7; // D672 jne 0xd6d7
            m.ww(m.bp +% 0xFFF6, m.si); // D674 mov word ptr [bp - 0xa], si
            m.si = m.di; // D677 mov si, di
            m.setAl(m.rb(0xA051)); // D679 mov al, byte ptr [0xa051]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // D67C sub ah, ah
            m.ax = m.sub(u16, m.ax, 0xA); // D67E sub ax, 0xa
            m.di = m.ax; // D681 mov di, ax
            m.wb(m.si +% 0x9EF6, 0x0); // D683 mov byte ptr [si - 0x610a], 0
            m.bx = m.di; // D688 mov bx, di
            m.cmp(u8, m.rb(m.bx +% 0x9EF6), 0x0); // D68A cmp byte ptr [bx - 0x610a], 0
            if (m.zf) continue :sw 0xD694; // D68F je 0xd694
            continue :sw 0xD7B8; // D691 jmp 0xd7b8
        },
        0xD694 => {
            m.mark(0xD694);
            m.push(0x1B); // D694 push 0x1b
            m.push(m.di); // D696 push di
            m.far(.see_white, 0xD697); // D697 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D69C or ax, ax
            if (m.sf != m.of) continue :sw 0xD6A3; // D69E jl 0xd6a3
            continue :sw 0xCE1C; // D6A0 jmp 0xce1c
        },
        0xD6A3 => {
            m.mark(0xD6A3);
            m.di = m.sub(u16, m.di, m.rw(m.bp +% 0xFFF6)); // D6A3 sub di, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D6A6 cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xD6BC; // D6AB jne 0xd6bc
            m.push(0x1B); // D6AD push 0x1b
            m.push(m.di); // D6AF push di
            m.far(.see_white, 0xD6B0); // D6B0 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D6B5 or ax, ax
            if (m.sf != m.of) continue :sw 0xD6D2; // D6B7 jl 0xd6d2
            continue :sw 0xCE1C; // D6B9 jmp 0xce1c
        },
        0xD6BC => {
            m.mark(0xD6BC);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // D6BC cmp byte ptr [di - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xD6D2; // D6C1 jle 0xd6d2
            m.push(0x1B); // D6C3 push 0x1b
            m.push(m.di); // D6C5 push di
            m.far(.see_white, 0xD6C6); // D6C6 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D6CB or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xD6D2; // D6CD jle 0xd6d2
            continue :sw 0xCE1F; // D6CF jmp 0xce1f
        },
        0xD6D2 => {
            m.mark(0xD6D2);
            m.wb(m.si +% 0x9EF6, 0x5); // D6D2 mov byte ptr [si - 0x610a], 5
            continue :sw 0xD6D7; // falls through
        },
        0xD6D7 => {
            m.mark(0xD6D7);
            m.setAl(m.rb(0xA22F)); // D6D7 mov al, byte ptr [0xa22f]
            m.cbw(); // D6DA cbw
            m.bx = m.rw(m.bp +% 0xFFF4); // D6DB mov bx, word ptr [bp - 0xc]
            m.bx = m.sub(u16, m.bx, m.ax); // D6DE sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0D4E)); // D6E0 mov al, byte ptr [bx + 0xd4e]
            m.cbw(); // D6E4 cbw
            m.si = m.ax; // D6E5 mov si, ax
            m.@"test"(u16, m.si, 0x2); // D6E7 test si, 2
            if (!m.zf) continue :sw 0xD6F0; // D6EB jne 0xd6f0
            continue :sw 0xD7DC; // D6ED jmp 0xd7dc
        },
        0xD6F0 => {
            m.mark(0xD6F0);
            m.setAl(m.rb(0xA051)); // D6F0 mov al, byte ptr [0xa051]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // D6F3 sub ah, ah
            m.di = m.ax; // D6F5 mov di, ax
            m.di = m.sub(u16, m.di, 0xA); // D6F7 sub di, 0xa
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // D6FA cmp byte ptr [di - 0x610a], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xD704; // D6FF jg 0xd704
            continue :sw 0xD8D7; // D701 jmp 0xd8d7
        },
        0xD704 => {
            m.mark(0xD704);
            m.si = m.di; // D704 mov si, di
            continue :sw 0xD706; // falls through
        },
        0xD706 => {
            m.mark(0xD706);
            m.si = m.sub(u16, m.si, 0xA); // D706 sub si, 0xa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D709 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD706; // D70E je 0xd706
            continue :sw 0xD710; // falls through
        },
        0xD710 => {
            m.mark(0xD710);
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // D710 cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xD718; // D713 je 0xd718
            continue :sw 0xD8D7; // D715 jmp 0xd8d7
        },
        0xD718 => {
            m.mark(0xD718);
            m.wb(m.si +% 0x9EF6, 0x0); // D718 mov byte ptr [si - 0x610a], 0
            continue :sw 0xD887; // D71D jmp 0xd887
        },
        0xD720 => {
            m.mark(0xD720);
            m.di = m.dec(u16, m.di); // D720 dec di
            m.bx = m.di; // D721 mov bx, di
            m.bx = m.add(u16, m.bx, m.si); // D723 add bx, si
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), 0x0); // D725 cmp byte ptr [bx + 0xab6], 0
            if (m.zf) continue :sw 0xD760; // D72A je 0xd760
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // D72C cmp byte ptr [di - 0x610a], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xD73A; // D731 jg 0xd73a
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D733 cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xD760; // D738 jne 0xd760
            continue :sw 0xD73A; // falls through
        },
        0xD73A => {
            m.mark(0xD73A);
            m.bx = m.di; // D73A mov bx, di
            m.bx = m.add(u16, m.bx, m.si); // D73C add bx, si
            m.setAl(m.rb(m.bx +% 0x0AB6)); // D73E mov al, byte ptr [bx + 0xab6]
            m.cbw(); // D742 cbw
            m.si = m.ax; // D743 mov si, ax
            continue :sw 0xD745; // falls through
        },
        0xD745 => {
            m.mark(0xD745);
            m.di = m.add(u16, m.di, m.si); // D745 add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D747 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xD745; // D74C je 0xd745
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.di); // D74E cmp word ptr [bp - 0xc], di
            if (!m.zf) continue :sw 0xD6D7; // D751 jne 0xd6d7
            m.si = m.di; // D753 mov si, di
            m.setAl(m.rb(0xA051)); // D755 mov al, byte ptr [0xa051]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // D758 sub ah, ah
            m.ax = m.sub(u16, m.ax, 0xB); // D75A sub ax, 0xb
            continue :sw 0xD7A8; // D75D jmp 0xd7a8
        },
        0xD760 => {
            m.mark(0xD760);
            m.di = m.add(u16, m.di, 0x2); // D760 add di, 2
            m.bx = m.di; // D763 mov bx, di
            m.bx = m.add(u16, m.bx, m.si); // D765 add bx, si
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), 0x0); // D767 cmp byte ptr [bx + 0xab6], 0
            if (!m.zf) continue :sw 0xD771; // D76C jne 0xd771
            continue :sw 0xD6D7; // D76E jmp 0xd6d7
        },
        0xD771 => {
            m.mark(0xD771);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // D771 cmp byte ptr [di - 0x610a], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xD782; // D776 jg 0xd782
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D778 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xD782; // D77D je 0xd782
            continue :sw 0xD6D7; // D77F jmp 0xd6d7
        },
        0xD782 => {
            m.mark(0xD782);
            m.bx = m.di; // D782 mov bx, di
            m.bx = m.add(u16, m.bx, m.si); // D784 add bx, si
            m.setAl(m.rb(m.bx +% 0x0AB6)); // D786 mov al, byte ptr [bx + 0xab6]
            m.cbw(); // D78A cbw
            m.si = m.ax; // D78B mov si, ax
            continue :sw 0xD78D; // falls through
        },
        0xD78D => {
            m.mark(0xD78D);
            m.di = m.add(u16, m.di, m.si); // D78D add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D78F cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xD78D; // D794 je 0xd78d
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.di); // D796 cmp word ptr [bp - 0xc], di
            if (m.zf) continue :sw 0xD79E; // D799 je 0xd79e
            continue :sw 0xD6D7; // D79B jmp 0xd6d7
        },
        0xD79E => {
            m.mark(0xD79E);
            m.si = m.di; // D79E mov si, di
            m.setAl(m.rb(0xA051)); // D7A0 mov al, byte ptr [0xa051]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // D7A3 sub ah, ah
            m.ax = m.sub(u16, m.ax, 0x9); // D7A5 sub ax, 9
            continue :sw 0xD7A8; // falls through
        },
        0xD7A8 => {
            m.mark(0xD7A8);
            m.di = m.ax; // D7A8 mov di, ax
            m.wb(m.si +% 0x9EF6, 0x0); // D7AA mov byte ptr [si - 0x610a], 0
            m.bx = m.di; // D7AF mov bx, di
            m.cmp(u8, m.rb(m.bx +% 0x9EF6), 0x0); // D7B1 cmp byte ptr [bx - 0x610a], 0
            if (m.zf) continue :sw 0xD7CA; // D7B6 je 0xd7ca
            continue :sw 0xD7B8; // falls through
        },
        0xD7B8 => {
            m.mark(0xD7B8);
            m.push(0x1B); // D7B8 push 0x1b
            m.push(m.di); // D7BA push di
            m.far(.see_white, 0xD7BB); // D7BB lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D7C0 or ax, ax
            if (!m.zf and m.sf == m.of) continue :sw 0xD7C7; // D7C2 jg 0xd7c7
            continue :sw 0xD6D2; // D7C4 jmp 0xd6d2
        },
        0xD7C7 => {
            m.mark(0xD7C7);
            continue :sw 0xD893; // D7C7 jmp 0xd893
        },
        0xD7CA => {
            m.mark(0xD7CA);
            m.push(0x1B); // D7CA push 0x1b
            m.push(m.di); // D7CC push di
            m.far(.see_white, 0xD7CD); // D7CD lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D7D2 or ax, ax
            if (m.sf != m.of) continue :sw 0xD7D9; // D7D4 jl 0xd7d9
            continue :sw 0xCE1C; // D7D6 jmp 0xce1c
        },
        0xD7D9 => {
            m.mark(0xD7D9);
            continue :sw 0xD6D2; // D7D9 jmp 0xd6d2
        },
        0xD7DC => {
            m.mark(0xD7DC);
            m.@"test"(u16, m.si, 0x4); // D7DC test si, 4
            if (m.zf) continue :sw 0xD84A; // D7E0 je 0xd84a
            m.setAl(m.rb(0xA051)); // D7E2 mov al, byte ptr [0xa051]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // D7E5 sub ah, ah
            m.di = m.ax; // D7E7 mov di, ax
            m.di = m.sub(u16, m.di, 0xB); // D7E9 sub di, 0xb
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // D7EC cmp byte ptr [di - 0x610a], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xD7FC; // D7F1 jg 0xd7fc
            m.cmp(u8, m.rb(m.di +% 0x9EF6), m.ah()); // D7F3 cmp byte ptr [di - 0x610a], ah
            if (m.zf) continue :sw 0xD7FC; // D7F7 je 0xd7fc
            continue :sw 0xD8D7; // D7F9 jmp 0xd8d7
        },
        0xD7FC => {
            m.mark(0xD7FC);
            m.si = m.di; // D7FC mov si, di
            continue :sw 0xD7FE; // falls through
        },
        0xD7FE => {
            m.mark(0xD7FE);
            m.si = m.sub(u16, m.si, 0xA); // D7FE sub si, 0xa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D801 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD7FE; // D806 je 0xd7fe
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // D808 cmp word ptr [bp - 0xc], si
            if (m.zf) continue :sw 0xD810; // D80B je 0xd810
            continue :sw 0xD8D7; // D80D jmp 0xd8d7
        },
        0xD810 => {
            m.mark(0xD810);
            m.wb(m.si +% 0x9EF6, 0x0); // D810 mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D815 cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xD887; // D81A jne 0xd887
            m.push(0x1B); // D81C push 0x1b
            m.push(m.di); // D81E push di
            m.far(.see_white, 0xD81F); // D81F lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D824 or ax, ax
            if (m.sf != m.of) continue :sw 0xD82B; // D826 jl 0xd82b
            continue :sw 0xCE1C; // D828 jmp 0xce1c
        },
        0xD82B => {
            m.mark(0xD82B);
            m.di = m.add(u16, m.di, 0xA); // D82B add di, 0xa
            continue :sw 0xD82E; // falls through
        },
        0xD82E => {
            m.mark(0xD82E);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D82E cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xD838; // D833 je 0xd838
            continue :sw 0xD8BC; // D835 jmp 0xd8bc
        },
        0xD838 => {
            m.mark(0xD838);
            m.push(0x1B); // D838 push 0x1b
            m.push(m.di); // D83A push di
            m.far(.see_white, 0xD83B); // D83B lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D840 or ax, ax
            if (m.sf == m.of) continue :sw 0xD847; // D842 jge 0xd847
            continue :sw 0xD8D2; // D844 jmp 0xd8d2
        },
        0xD847 => {
            m.mark(0xD847);
            continue :sw 0xCE1C; // D847 jmp 0xce1c
        },
        0xD84A => {
            m.mark(0xD84A);
            m.@"test"(u16, m.si, 0x1); // D84A test si, 1
            if (!m.zf) continue :sw 0xD853; // D84E jne 0xd853
            continue :sw 0xD8D7; // D850 jmp 0xd8d7
        },
        0xD853 => {
            m.mark(0xD853);
            m.setAl(m.rb(0xA051)); // D853 mov al, byte ptr [0xa051]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // D856 sub ah, ah
            m.di = m.ax; // D858 mov di, ax
            m.di = m.sub(u16, m.di, 0x9); // D85A sub di, 9
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // D85D cmp byte ptr [di - 0x610a], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xD86A; // D862 jg 0xd86a
            m.cmp(u8, m.rb(m.di +% 0x9EF6), m.ah()); // D864 cmp byte ptr [di - 0x610a], ah
            if (!m.zf) continue :sw 0xD8D7; // D868 jne 0xd8d7
            continue :sw 0xD86A; // falls through
        },
        0xD86A => {
            m.mark(0xD86A);
            m.si = m.di; // D86A mov si, di
            continue :sw 0xD86C; // falls through
        },
        0xD86C => {
            m.mark(0xD86C);
            m.si = m.sub(u16, m.si, 0xA); // D86C sub si, 0xa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D86F cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD86C; // D874 je 0xd86c
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), m.si); // D876 cmp word ptr [bp - 0xc], si
            if (!m.zf) continue :sw 0xD8D7; // D879 jne 0xd8d7
            m.wb(m.si +% 0x9EF6, 0x0); // D87B mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D880 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xD8A0; // D885 je 0xd8a0
            continue :sw 0xD887; // falls through
        },
        0xD887 => {
            m.mark(0xD887);
            m.push(0x1B); // D887 push 0x1b
            m.push(m.di); // D889 push di
            m.far(.see_white, 0xD88A); // D88A lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D88F or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xD8D2; // D891 jle 0xd8d2
            continue :sw 0xD893; // falls through
        },
        0xD893 => {
            m.mark(0xD893);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x8); // D893 cmp byte ptr [di - 0x610a], 8
            continue :sw 0xD898; // falls through
        },
        0xD898 => {
            m.mark(0xD898);
            if (m.zf) continue :sw 0xD89D; // D898 je 0xd89d
            continue :sw 0xCE1F; // D89A jmp 0xce1f
        },
        0xD89D => {
            m.mark(0xD89D);
            continue :sw 0xCE1C; // D89D jmp 0xce1c
        },
        0xD8A0 => {
            m.mark(0xD8A0);
            m.push(0x1B); // D8A0 push 0x1b
            m.push(m.di); // D8A2 push di
            m.far(.see_white, 0xD8A3); // D8A3 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D8A8 or ax, ax
            if (m.sf != m.of) continue :sw 0xD8AF; // D8AA jl 0xd8af
            continue :sw 0xCE1C; // D8AC jmp 0xce1c
        },
        0xD8AF => {
            m.mark(0xD8AF);
            m.di = m.add(u16, m.di, 0xA); // D8AF add di, 0xa
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D8B2 cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xD8BC; // D8B7 jne 0xd8bc
            continue :sw 0xD838; // D8B9 jmp 0xd838
        },
        0xD8BC => {
            m.mark(0xD8BC);
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // D8BC cmp byte ptr [di - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xD8D2; // D8C1 jle 0xd8d2
            continue :sw 0xD8C3; // falls through
        },
        0xD8C3 => {
            m.mark(0xD8C3);
            m.push(0x1B); // D8C3 push 0x1b
            m.push(m.di); // D8C5 push di
            m.far(.see_white, 0xD8C6); // D8C6 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D8CB or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xD8D2; // D8CD jle 0xd8d2
            continue :sw 0xCE1F; // D8CF jmp 0xce1f
        },
        0xD8D2 => {
            m.mark(0xD8D2);
            m.wb(m.si +% 0x9EF6, 0x5); // D8D2 mov byte ptr [si - 0x610a], 5
            continue :sw 0xD8D7; // falls through
        },
        0xD8D7 => {
            m.mark(0xD8D7);
            m.setAl(m.rb(0xA051)); // D8D7 mov al, byte ptr [0xa051]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // D8DA sub ah, ah
            m.di = m.ax; // D8DC mov di, ax
            continue :sw 0xD8DE; // falls through
        },
        0xD8DE => {
            m.mark(0xD8DE);
            m.cmp(u16, m.di, 0x5B); // D8DE cmp di, 0x5b
            if (m.sf != m.of) continue :sw 0xD8E6; // D8E1 jl 0xd8e6
            continue :sw 0xD968; // D8E3 jmp 0xd968
        },
        0xD8E6 => {
            m.mark(0xD8E6);
            m.cmp(u8, m.rb(m.di +% 0x9F00), 0x0); // D8E6 cmp byte ptr [di - 0x6100], 0
            if (m.zf) continue :sw 0xD8F0; // D8EB je 0xd8f0
            continue :sw 0xDAE8; // D8ED jmp 0xdae8
        },
        0xD8F0 => {
            m.mark(0xD8F0);
            m.cmp(u8, m.rb(0xA03E), 0x5B); // D8F0 cmp byte ptr [0xa03e], 0x5b
            if (m.cf) continue :sw 0xD8FE; // D8F5 jb 0xd8fe
            m.cmp(u8, m.rb(0xA03E), 0x62); // D8F7 cmp byte ptr [0xa03e], 0x62
            if (m.cf or m.zf) continue :sw 0xD912; // D8FC jbe 0xd912
            continue :sw 0xD8FE; // falls through
        },
        0xD8FE => {
            m.mark(0xD8FE);
            m.cmp(u8, m.rb(0xA03F), 0x5B); // D8FE cmp byte ptr [0xa03f], 0x5b
            if (!m.cf) continue :sw 0xD908; // D903 jae 0xd908
            continue :sw 0xDAE8; // D905 jmp 0xdae8
        },
        0xD908 => {
            m.mark(0xD908);
            m.cmp(u8, m.rb(0xA03F), 0x62); // D908 cmp byte ptr [0xa03f], 0x62
            if (m.cf or m.zf) continue :sw 0xD912; // D90D jbe 0xd912
            continue :sw 0xDAE8; // D90F jmp 0xdae8
        },
        0xD912 => {
            m.mark(0xD912);
            m.cmp(u16, m.di, 0x57); // D912 cmp di, 0x57
            if (m.sf != m.of) continue :sw 0xD950; // D915 jl 0xd950
            m.si = m.di +% 0x0009; // D917 lea si, [di + 9]
            continue :sw 0xD91F; // D91A jmp 0xd91f
        },
        0xD91E => {
            m.mark(0xD91E);
            m.si = m.dec(u16, m.si); // D91E dec si
            continue :sw 0xD91F; // falls through
        },
        0xD91F => {
            m.mark(0xD91F);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D91F cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD91E; // D924 je 0xd91e
            continue :sw 0xD926; // falls through
        },
        0xD926 => {
            m.mark(0xD926);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x4); // D926 cmp byte ptr [si - 0x610a], 4
            if (m.zf) continue :sw 0xD930; // D92B je 0xd930
            continue :sw 0xDAE8; // D92D jmp 0xdae8
        },
        0xD930 => {
            m.mark(0xD930);
            m.wb(m.si +% 0x9EF6, 0x0); // D930 mov byte ptr [si - 0x610a], 0
            m.push(0xF); // D935 push 0xf
            m.ax = m.di +% 0x000A; // D937 lea ax, [di + 0xa]
            m.push(m.ax); // D93A push ax
            continue :sw 0xD93B; // falls through
        },
        0xD93B => {
            m.mark(0xD93B);
            m.far(.see_white, 0xD93B); // D93B lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D940 or ax, ax
            if (m.sf != m.of) continue :sw 0xD947; // D942 jl 0xd947
            continue :sw 0xD1A6; // D944 jmp 0xd1a6
        },
        0xD947 => {
            m.mark(0xD947);
            m.wb(m.si +% 0x9EF6, 0x4); // D947 mov byte ptr [si - 0x610a], 4
            continue :sw 0xDAE8; // D94C jmp 0xdae8
        },
        0xD950 => {
            m.mark(0xD950);
            m.cmp(u16, m.di, 0x52); // D950 cmp di, 0x52
            if (m.zf or m.sf != m.of) continue :sw 0xD958; // D953 jle 0xd958
            continue :sw 0xDAE8; // D955 jmp 0xdae8
        },
        0xD958 => {
            m.mark(0xD958);
            m.si = m.di +% 0x000B; // D958 lea si, [di + 0xb]
            continue :sw 0xD95F; // D95B jmp 0xd95f
        },
        0xD95E => {
            m.mark(0xD95E);
            m.si = m.inc(u16, m.si); // D95E inc si
            continue :sw 0xD95F; // falls through
        },
        0xD95F => {
            m.mark(0xD95F);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D95F cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD95E; // D964 je 0xd95e
            continue :sw 0xD926; // D966 jmp 0xd926
        },
        0xD968 => {
            m.mark(0xD968);
            m.di = m.sub(u16, m.di, 0xA); // D968 sub di, 0xa
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // D96B cmp byte ptr [di - 0x610a], 7
            if (m.zf or m.sf != m.of) continue :sw 0xD9AE; // D970 jle 0xd9ae
            m.setAl(m.rb(0xA22F)); // D972 mov al, byte ptr [0xa22f]
            m.cbw(); // D975 cbw
            m.bx = m.ax; // D976 mov bx, ax
            m.cmp(u8, m.rb(m.bx +% 0xA8C8), 0x0); // D978 cmp byte ptr [bx - 0x5738], 0
            if (!m.zf) continue :sw 0xD9AE; // D97D jne 0xd9ae
            m.si = m.di +% 0xFFF6; // D97F lea si, [di - 0xa]
            continue :sw 0xD987; // D982 jmp 0xd987
        },
        0xD984 => {
            m.mark(0xD984);
            m.si = m.sub(u16, m.si, 0xA); // D984 sub si, 0xa
            continue :sw 0xD987; // falls through
        },
        0xD987 => {
            m.mark(0xD987);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D987 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD984; // D98C je 0xd984
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x4); // D98E cmp byte ptr [si - 0x610a], 4
            if (!m.zf) continue :sw 0xD9AE; // D993 jne 0xd9ae
            m.wb(m.si +% 0x9EF6, 0x0); // D995 mov byte ptr [si - 0x610a], 0
            m.push(0xF); // D99A push 0xf
            m.push(m.di); // D99C push di
            m.far(.see_white, 0xD99D); // D99D lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D9A2 or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xD9A9; // D9A4 jle 0xd9a9
            continue :sw 0xD1A6; // D9A6 jmp 0xd1a6
        },
        0xD9A9 => {
            m.mark(0xD9A9);
            m.wb(m.si +% 0x9EF6, 0x4); // D9A9 mov byte ptr [si - 0x610a], 4
            continue :sw 0xD9AE; // falls through
        },
        0xD9AE => {
            m.mark(0xD9AE);
            m.di = m.add(u16, m.di, 0xB); // D9AE add di, 0xb
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D9B1 cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xD9EE; // D9B6 jne 0xd9ee
            m.si = m.di; // D9B8 mov si, di
            continue :sw 0xD9BA; // falls through
        },
        0xD9BA => {
            m.mark(0xD9BA);
            m.si = m.sub(u16, m.si, 0xA); // D9BA sub si, 0xa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D9BD cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD9BA; // D9C2 je 0xd9ba
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x4); // D9C4 cmp byte ptr [si - 0x610a], 4
            if (!m.zf) continue :sw 0xD9EE; // D9C9 jne 0xd9ee
            m.wb(m.si +% 0x9EF6, 0x0); // D9CB mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // D9D0 cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xD9DA; // D9D5 je 0xd9da
            continue :sw 0xD1A6; // D9D7 jmp 0xd1a6
        },
        0xD9DA => {
            m.mark(0xD9DA);
            m.push(0xF); // D9DA push 0xf
            m.push(m.di); // D9DC push di
            m.far(.see_white, 0xD9DD); // D9DD lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // D9E2 or ax, ax
            if (m.sf != m.of) continue :sw 0xD9E9; // D9E4 jl 0xd9e9
            continue :sw 0xD1A6; // D9E6 jmp 0xd1a6
        },
        0xD9E9 => {
            m.mark(0xD9E9);
            m.wb(m.si +% 0x9EF6, 0x4); // D9E9 mov byte ptr [si - 0x610a], 4
            continue :sw 0xD9EE; // falls through
        },
        0xD9EE => {
            m.mark(0xD9EE);
            m.di = m.sub(u16, m.di, 0x2); // D9EE sub di, 2
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // D9F1 cmp byte ptr [di - 0x610a], 0
            if (!m.zf) continue :sw 0xDA2E; // D9F6 jne 0xda2e
            m.si = m.di; // D9F8 mov si, di
            continue :sw 0xD9FA; // falls through
        },
        0xD9FA => {
            m.mark(0xD9FA);
            m.si = m.sub(u16, m.si, 0xA); // D9FA sub si, 0xa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // D9FD cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xD9FA; // DA02 je 0xd9fa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x4); // DA04 cmp byte ptr [si - 0x610a], 4
            if (!m.zf) continue :sw 0xDA2E; // DA09 jne 0xda2e
            m.wb(m.si +% 0x9EF6, 0x0); // DA0B mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // DA10 cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xDA1A; // DA15 je 0xda1a
            continue :sw 0xD1A6; // DA17 jmp 0xd1a6
        },
        0xDA1A => {
            m.mark(0xDA1A);
            m.push(0xF); // DA1A push 0xf
            m.push(m.di); // DA1C push di
            m.far(.see_white, 0xDA1D); // DA1D lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // DA22 or ax, ax
            if (m.sf != m.of) continue :sw 0xDA29; // DA24 jl 0xda29
            continue :sw 0xD1A6; // DA26 jmp 0xd1a6
        },
        0xDA29 => {
            m.mark(0xDA29);
            m.wb(m.si +% 0x9EF6, 0x4); // DA29 mov byte ptr [si - 0x610a], 4
            continue :sw 0xDA2E; // falls through
        },
        0xDA2E => {
            m.mark(0xDA2E);
            m.cmp(u8, m.rb(0xA03E), 0x51); // DA2E cmp byte ptr [0xa03e], 0x51
            if (m.cf) continue :sw 0xDA3C; // DA33 jb 0xda3c
            m.cmp(u8, m.rb(0xA03E), 0x58); // DA35 cmp byte ptr [0xa03e], 0x58
            if (m.cf or m.zf) continue :sw 0xDA50; // DA3A jbe 0xda50
            continue :sw 0xDA3C; // falls through
        },
        0xDA3C => {
            m.mark(0xDA3C);
            m.cmp(u8, m.rb(0xA03F), 0x51); // DA3C cmp byte ptr [0xa03f], 0x51
            if (!m.cf) continue :sw 0xDA46; // DA41 jae 0xda46
            continue :sw 0xDAE8; // DA43 jmp 0xdae8
        },
        0xDA46 => {
            m.mark(0xDA46);
            m.cmp(u8, m.rb(0xA03F), 0x58); // DA46 cmp byte ptr [0xa03f], 0x58
            if (m.cf or m.zf) continue :sw 0xDA50; // DA4B jbe 0xda50
            continue :sw 0xDAE8; // DA4D jmp 0xdae8
        },
        0xDA50 => {
            m.mark(0xDA50);
            m.di = m.sub(u16, m.di, 0x9); // DA50 sub di, 9
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x7); // DA53 cmp byte ptr [di - 0x610a], 7
            if (!m.zf and m.sf == m.of) continue :sw 0xDA64; // DA58 jg 0xda64
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // DA5A cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xDA64; // DA5F je 0xda64
            continue :sw 0xDAE8; // DA61 jmp 0xdae8
        },
        0xDA64 => {
            m.mark(0xDA64);
            m.si = m.di; // DA64 mov si, di
            continue :sw 0xDA66; // falls through
        },
        0xDA66 => {
            m.mark(0xDA66);
            m.si = m.dec(u16, m.si); // DA66 dec si
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // DA67 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xDA66; // DA6C je 0xda66
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x4); // DA6E cmp byte ptr [si - 0x610a], 4
            if (!m.zf) continue :sw 0xDAA6; // DA73 jne 0xdaa6
            m.wb(m.si +% 0x9EF6, 0x0); // DA75 mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // DA7A cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xDA92; // DA7F je 0xda92
            m.push(0xF); // DA81 push 0xf
            m.push(m.di); // DA83 push di
            m.far(.see_white, 0xDA84); // DA84 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // DA89 or ax, ax
            if (m.zf or m.sf != m.of) continue :sw 0xDAA1; // DA8B jle 0xdaa1
            continue :sw 0xD1A6; // DA8D jmp 0xd1a6
        },
        0xDA92 => {
            m.mark(0xDA92);
            m.push(0xF); // DA92 push 0xf
            m.push(m.di); // DA94 push di
            m.far(.see_white, 0xDA95); // DA95 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // DA9A or ax, ax
            if (m.sf != m.of) continue :sw 0xDAA1; // DA9C jl 0xdaa1
            continue :sw 0xD1A6; // DA9E jmp 0xd1a6
        },
        0xDAA1 => {
            m.mark(0xDAA1);
            m.wb(m.si +% 0x9EF6, 0x4); // DAA1 mov byte ptr [si - 0x610a], 4
            continue :sw 0xDAA6; // falls through
        },
        0xDAA6 => {
            m.mark(0xDAA6);
            m.si = m.di; // DAA6 mov si, di
            continue :sw 0xDAA8; // falls through
        },
        0xDAA8 => {
            m.mark(0xDAA8);
            m.si = m.inc(u16, m.si); // DAA8 inc si
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // DAA9 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xDAA8; // DAAE je 0xdaa8
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x4); // DAB0 cmp byte ptr [si - 0x610a], 4
            if (!m.zf) continue :sw 0xDAE8; // DAB5 jne 0xdae8
            m.wb(m.si +% 0x9EF6, 0x0); // DAB7 mov byte ptr [si - 0x610a], 0
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // DABC cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xDAD6; // DAC1 je 0xdad6
            m.push(0xF); // DAC3 push 0xf
            m.push(m.di); // DAC5 push di
            m.far(.see_white, 0xDAC6); // DAC6 lcall 0x2b9f, 0xc32a
            m.ax = m.@"or"(u16, m.ax, m.ax); // DACB or ax, ax
            if (!m.zf and m.sf == m.of) continue :sw 0xDAD2; // DACD jg 0xdad2
            continue :sw 0xD947; // DACF jmp 0xd947
        },
        0xDAD2 => {
            m.mark(0xDAD2);
            continue :sw 0xD1A6; // DAD2 jmp 0xd1a6
        },
        0xDAD6 => {
            m.mark(0xDAD6);
            m.push(0xF); // DAD6 push 0xf
            m.push(m.di); // DAD8 push di
            continue :sw 0xD93B; // DAD9 jmp 0xd93b
        },
        0xDADC => {
            m.mark(0xDADC);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x3C)); // DADC add word ptr [bp - 4], 0x3c
            continue :sw 0xDAE0; // falls through
        },
        0xDAE0 => {
            m.mark(0xDAE0);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x1E)); // DAE0 add word ptr [bp - 2], 0x1e
            continue :sw 0xDAE4; // falls through
        },
        0xDAE4 => {
            m.mark(0xDAE4);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x1E)); // DAE4 add word ptr [bp - 2], 0x1e
            continue :sw 0xDAE8; // falls through
        },
        0xDAE8 => {
            m.mark(0xDAE8);
            m.cmp(u8, m.rb(0x931B), 0x0); // DAE8 cmp byte ptr [0x931b], 0
            if (!m.zf) continue :sw 0xDB24; // DAED jne 0xdb24
            continue :sw 0xDAEF; // falls through
        },
        0xDAEF => {
            m.mark(0xDAEF);
            m.ax = m.rw(m.bp +% 0xFFFE); // DAEF mov ax, word ptr [bp - 2]
            m.si = m.pop(); // DAF2 pop si
            m.di = m.pop(); // DAF3 pop di
            m.sp = m.bp;
            m.bp = m.pop(); // DAF4 leave
            return; // DAF5 retf
        },
        0xDAF6 => {
            m.mark(0xDAF6);
            m.ax = m.rw(0xA272); // DAF6 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // DAF9 cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xDB15; // DAFC jle 0xdb15
            m.cmp(u8, m.rb(0xA40E), 0x0); // DAFE cmp byte ptr [0xa40e], 0
            if (!m.zf) continue :sw 0xDB15; // DB03 jne 0xdb15
            m.ax = m.rw(0x9356); // DB05 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // DB08 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xDAE0; // DB0B jg 0xdae0
            m.cmp(u16, m.rw(0xAE38), 0xED8); // DB0D cmp word ptr [0xae38], 0xed8
            if (!m.zf and m.sf == m.of) continue :sw 0xDAE0; // DB13 jg 0xdae0
            continue :sw 0xDB15; // falls through
        },
        0xDB15 => {
            m.mark(0xDB15);
            m.bx = m.rw(m.bp +% 0x000A); // DB15 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // DB18 inc byte ptr [bx]
            m.ax = m.rw(m.bp +% 0xFFFE); // DB1A mov ax, word ptr [bp - 2]
            m.ax = m.add(u16, m.ax, 0x1388); // DB1D add ax, 0x1388
            m.si = m.pop(); // DB20 pop si
            m.di = m.pop(); // DB21 pop di
            m.sp = m.bp;
            m.bp = m.pop(); // DB22 leave
            return; // DB23 retf
        },
        0xDB24 => {
            m.mark(0xDB24);
            m.cmp(u16, m.rw(0x378E), 0x1838); // DB24 cmp word ptr [0x378e], 0x1838
            if (!m.cf) continue :sw 0xDB2F; // DB2A jae 0xdb2f
            continue :sw 0xDBDE; // DB2C jmp 0xdbde
        },
        0xDB2F => {
            m.mark(0xDB2F);
            m.cmp(u8, m.rb(0x9F2D), 0x8); // DB2F cmp byte ptr [0x9f2d], 8
            if (!m.zf) continue :sw 0xDB82; // DB34 jne 0xdb82
            m.cmp(u8, m.rb(0x3811), 0x0); // DB36 cmp byte ptr [0x3811], 0
            if (!m.zf) continue :sw 0xDB82; // DB3B jne 0xdb82
            m.cmp(u8, m.rb(0xA553), 0x0); // DB3D cmp byte ptr [0xa553], 0
            if (!m.zf) continue :sw 0xDB6C; // DB42 jne 0xdb6c
            m.bx = 0xA9F; // DB44 mov bx, 0xa9f
            m.setAl(m.rb(0xA03A)); // DB47 mov al, byte ptr [0xa03a]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // DB4A sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // DB4C sub bx, ax
            m.setAl(m.rb(m.bx)); // DB4E mov al, byte ptr [bx]
            m.bx = 0xA9F; // DB50 mov bx, 0xa9f
            m.setCl(m.rb(0xA03B)); // DB53 mov cl, byte ptr [0xa03b]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // DB57 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // DB59 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx))); // DB5B or al, byte ptr [bx]
            if (m.zf) continue :sw 0xDB82; // DB5D je 0xdb82
            m.push(0x6); // DB5F push 6
            m.push(0x37); // DB61 push 0x37
            m.far(.att_4cec, 0xDB63); // DB63 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // DB68 or ax, ax
            if (m.sf == m.of) continue :sw 0xDB82; // DB6A jge 0xdb82
            continue :sw 0xDB6C; // falls through
        },
        0xDB6C => {
            m.mark(0xDB6C);
            m.ax = m.rw(0xA272); // DB6C mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // DB6F cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xDB7E; // DB72 jg 0xdb7e
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x12C)); // DB74 add word ptr [bp - 2], 0x12c
            m.bx = m.rw(m.bp +% 0x000A); // DB79 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // DB7C inc byte ptr [bx]
            continue :sw 0xDB7E; // falls through
        },
        0xDB7E => {
            m.mark(0xDB7E);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x28)); // DB7E add word ptr [bp - 4], 0x28
            continue :sw 0xDB82; // falls through
        },
        0xDB82 => {
            m.mark(0xDB82);
            m.cmp(u8, m.rb(0x9F2C), 0x8); // DB82 cmp byte ptr [0x9f2c], 8
            if (m.zf) continue :sw 0xDB8C; // DB87 je 0xdb8c
            continue :sw 0xDD5C; // DB89 jmp 0xdd5c
        },
        0xDB8C => {
            m.mark(0xDB8C);
            m.cmp(u8, m.rb(0x3810), 0x0); // DB8C cmp byte ptr [0x3810], 0
            if (m.zf) continue :sw 0xDB96; // DB91 je 0xdb96
            continue :sw 0xDD5C; // DB93 jmp 0xdd5c
        },
        0xDB96 => {
            m.mark(0xDB96);
            m.cmp(u8, m.rb(0xA552), 0x0); // DB96 cmp byte ptr [0xa552], 0
            if (!m.zf) continue :sw 0xDBCB; // DB9B jne 0xdbcb
            m.bx = 0xA9E; // DB9D mov bx, 0xa9e
            m.setAl(m.rb(0xA03A)); // DBA0 mov al, byte ptr [0xa03a]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // DBA3 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // DBA5 sub bx, ax
            m.setAl(m.rb(m.bx)); // DBA7 mov al, byte ptr [bx]
            m.bx = 0xA9E; // DBA9 mov bx, 0xa9e
            m.setCl(m.rb(0xA03B)); // DBAC mov cl, byte ptr [0xa03b]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // DBB0 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // DBB2 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx))); // DBB4 or al, byte ptr [bx]
            if (!m.zf) continue :sw 0xDBBB; // DBB6 jne 0xdbbb
            continue :sw 0xDD5C; // DBB8 jmp 0xdd5c
        },
        0xDBBB => {
            m.mark(0xDBBB);
            m.push(0x6); // DBBB push 6
            m.push(0x36); // DBBD push 0x36
            m.far(.att_4cec, 0xDBBF); // DBBF lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // DBC4 or ax, ax
            if (m.sf != m.of) continue :sw 0xDBCB; // DBC6 jl 0xdbcb
            continue :sw 0xDD5C; // DBC8 jmp 0xdd5c
        },
        0xDBCB => {
            m.mark(0xDBCB);
            m.ax = m.rw(0xA272); // DBCB mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // DBCE cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xDBD6; // DBD1 jle 0xdbd6
            continue :sw 0xDD58; // DBD3 jmp 0xdd58
        },
        0xDBD6 => {
            m.mark(0xDBD6);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x12C)); // DBD6 add word ptr [bp - 2], 0x12c
            continue :sw 0xDD53; // DBDB jmp 0xdd53
        },
        0xDBDE => {
            m.mark(0xDBDE);
            m.cmp(u8, m.rb(0x931A), 0x0); // DBDE cmp byte ptr [0x931a], 0
            if (!m.zf) continue :sw 0xDBE8; // DBE3 jne 0xdbe8
            continue :sw 0xDD5C; // DBE5 jmp 0xdd5c
        },
        0xDBE8 => {
            m.mark(0xDBE8);
            m.cmp(u16, m.rw(0xAE38), 0x44C); // DBE8 cmp word ptr [0xae38], 0x44c
            if (!m.zf) continue :sw 0xDC54; // DBEE jne 0xdc54
            continue :sw 0xDBF0; // falls through
        },
        0xDBF0 => {
            m.mark(0xDBF0);
            m.setBl(m.rb(0x8EB6)); // DBF0 mov bl, byte ptr [0x8eb6]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // DBF4 sub bh, bh
            m.setAl(m.rb(m.bx +% 0x01AC)); // DBF6 mov al, byte ptr [bx + 0x1ac]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // DBFA sub ah, ah
            m.di = m.ax; // DBFC mov di, ax
            m.di = m.@"or"(u16, m.di, m.di); // DBFE or di, di
            if (!m.zf) continue :sw 0xDC05; // DC00 jne 0xdc05
            continue :sw 0xDD5C; // DC02 jmp 0xdd5c
        },
        0xDC05 => {
            m.mark(0xDC05);
            m.setAl(m.rb(m.di +% 0x019C)); // DC05 mov al, byte ptr [di + 0x19c]
            m.wb(0x8EB6, m.@"and"(u8, m.rb(0x8EB6), m.al())); // DC09 and byte ptr [0x8eb6], al
            m.setAl(m.rb(m.di +% 0xA04A)); // DC0D mov al, byte ptr [di - 0x5fb6]
            m.di = m.ax; // DC11 mov di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x8); // DC13 cmp byte ptr [di - 0x610a], 8
            if (!m.zf) continue :sw 0xDBF0; // DC18 jne 0xdbf0
            m.si = m.di +% 0x00B0; // DC1A lea si, [di + 0xb0]
            m.bx = m.si; // DC1E mov bx, si
            m.setAl(m.rb(0xA03E)); // DC20 mov al, byte ptr [0xa03e]
            m.bx = m.sub(u16, m.bx, m.ax); // DC23 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0BB4)); // DC25 mov al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // DC29 mov bx, si
            m.setCl(m.rb(0xA03F)); // DC2B mov cl, byte ptr [0xa03f]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // DC2F sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // DC31 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // DC33 or al, byte ptr [bx + 0xbb4]
            if (m.zf) continue :sw 0xDBF0; // DC37 je 0xdbf0
            m.push(0x6); // DC39 push 6
            m.push(m.di); // DC3B push di
            m.far(.att_4cec, 0xDC3C); // DC3C lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // DC41 or ax, ax
            if (m.sf == m.of) continue :sw 0xDBF0; // DC43 jge 0xdbf0
            m.ax = m.rw(0x9356); // DC45 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // DC48 cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xDC50; // DC4B jl 0xdc50
            continue :sw 0xDD58; // DC4D jmp 0xdd58
        },
        0xDC50 => {
            m.mark(0xDC50);
            continue :sw 0xDD3E; // DC50 jmp 0xdd3e
        },
        0xDC54 => {
            m.mark(0xDC54);
            m.cmp(u16, m.rw(m.bp +% 0xFFF4), 0x62); // DC54 cmp word ptr [bp - 0xc], 0x62
            if (!m.zf and m.sf == m.of) continue :sw 0xDC5D; // DC58 jg 0xdc5d
            continue :sw 0xDCE8; // DC5A jmp 0xdce8
        },
        0xDC5D => {
            m.mark(0xDC5D);
            m.setBl(m.rb(0x8EB6)); // DC5D mov bl, byte ptr [0x8eb6]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // DC61 sub bh, bh
            m.setAl(m.rb(m.bx +% 0x01AC)); // DC63 mov al, byte ptr [bx + 0x1ac]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // DC67 sub ah, ah
            m.di = m.ax; // DC69 mov di, ax
            m.di = m.@"or"(u16, m.di, m.di); // DC6B or di, di
            if (!m.zf) continue :sw 0xDC72; // DC6D jne 0xdc72
            continue :sw 0xDD5C; // DC6F jmp 0xdd5c
        },
        0xDC72 => {
            m.mark(0xDC72);
            m.setAl(m.rb(m.di +% 0x019C)); // DC72 mov al, byte ptr [di + 0x19c]
            m.wb(0x8EB6, m.@"and"(u8, m.rb(0x8EB6), m.al())); // DC76 and byte ptr [0x8eb6], al
            m.setAl(m.rb(m.di +% 0xA04A)); // DC7A mov al, byte ptr [di - 0x5fb6]
            m.di = m.ax; // DC7E mov di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x8); // DC80 cmp byte ptr [di - 0x610a], 8
            if (!m.zf) continue :sw 0xDC5D; // DC85 jne 0xdc5d
            m.si = m.di +% 0x00B0; // DC87 lea si, [di + 0xb0]
            m.bx = m.si; // DC8B mov bx, si
            m.setAl(m.rb(0xA03E)); // DC8D mov al, byte ptr [0xa03e]
            m.bx = m.sub(u16, m.bx, m.ax); // DC90 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0BB4)); // DC92 mov al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // DC96 mov bx, si
            m.setCl(m.rb(0xA03F)); // DC98 mov cl, byte ptr [0xa03f]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // DC9C sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // DC9E sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // DCA0 or al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // DCA4 mov bx, si
            m.setCl(m.rb(0xA03C)); // DCA6 mov cl, byte ptr [0xa03c]
            m.bx = m.sub(u16, m.bx, m.cx); // DCAA sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // DCAC or al, byte ptr [bx + 0xab6]
            m.bx = m.si; // DCB0 mov bx, si
            m.setCl(m.rb(0xA03D)); // DCB2 mov cl, byte ptr [0xa03d]
            m.bx = m.sub(u16, m.bx, m.cx); // DCB6 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // DCB8 or al, byte ptr [bx + 0xab6]
            m.bx = m.si; // DCBC mov bx, si
            m.setCl(m.rb(0xA03B)); // DCBE mov cl, byte ptr [0xa03b]
            m.bx = m.sub(u16, m.bx, m.cx); // DCC2 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // DCC4 or al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // DCC8 mov bx, si
            m.setCl(m.rb(0xA03A)); // DCCA mov cl, byte ptr [0xa03a]
            m.bx = m.sub(u16, m.bx, m.cx); // DCCE sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // DCD0 or al, byte ptr [bx + 0x9b8]
            if (m.zf) continue :sw 0xDC5D; // DCD4 je 0xdc5d
            m.push(0x6); // DCD6 push 6
            m.push(m.di); // DCD8 push di
            m.far(.att_4cec, 0xDCD9); // DCD9 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // DCDE or ax, ax
            if (m.sf != m.of) continue :sw 0xDCE5; // DCE0 jl 0xdce5
            continue :sw 0xDC5D; // DCE2 jmp 0xdc5d
        },
        0xDCE5 => {
            m.mark(0xDCE5);
            continue :sw 0xDD36; // DCE5 jmp 0xdd36
        },
        0xDCE8 => {
            m.mark(0xDCE8);
            m.cmp(u16, m.rw(0xAE38), 0x7D0); // DCE8 cmp word ptr [0xae38], 0x7d0
            if (!m.zf) continue :sw 0xDD5C; // DCEE jne 0xdd5c
            continue :sw 0xDCF0; // falls through
        },
        0xDCF0 => {
            m.mark(0xDCF0);
            m.setBl(m.rb(0x8EB6)); // DCF0 mov bl, byte ptr [0x8eb6]
            m.setBh(m.sub(u8, m.bh(), m.bh())); // DCF4 sub bh, bh
            m.setAl(m.rb(m.bx +% 0x01AC)); // DCF6 mov al, byte ptr [bx + 0x1ac]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // DCFA sub ah, ah
            m.di = m.ax; // DCFC mov di, ax
            m.di = m.@"or"(u16, m.di, m.di); // DCFE or di, di
            if (m.zf) continue :sw 0xDD5C; // DD00 je 0xdd5c
            m.setAl(m.rb(m.di +% 0x019C)); // DD02 mov al, byte ptr [di + 0x19c]
            m.wb(0x8EB6, m.@"and"(u8, m.rb(0x8EB6), m.al())); // DD06 and byte ptr [0x8eb6], al
            m.setAl(m.rb(m.di +% 0xA04A)); // DD0A mov al, byte ptr [di - 0x5fb6]
            m.di = m.ax; // DD0E mov di, ax
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x8); // DD10 cmp byte ptr [di - 0x610a], 8
            if (!m.zf) continue :sw 0xDCF0; // DD15 jne 0xdcf0
            m.si = m.di +% 0x00B0; // DD17 lea si, [di + 0xb0]
            m.bx = m.si; // DD1B mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // DD1D sub bx, word ptr [bp - 0xc]
            m.setAl(m.rb(m.bx +% 0x0BB4)); // DD20 mov al, byte ptr [bx + 0xbb4]
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // DD24 or al, byte ptr [bx + 0xab6]
            if (m.zf) continue :sw 0xDCF0; // DD28 je 0xdcf0
            m.push(0x6); // DD2A push 6
            m.push(m.di); // DD2C push di
            m.far(.att_4cec, 0xDD2D); // DD2D lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // DD32 or ax, ax
            if (m.sf == m.of) continue :sw 0xDCF0; // DD34 jge 0xdcf0
            continue :sw 0xDD36; // falls through
        },
        0xDD36 => {
            m.mark(0xDD36);
            m.ax = m.rw(0xA272); // DD36 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // DD39 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xDD58; // DD3C jg 0xdd58
            continue :sw 0xDD3E; // falls through
        },
        0xDD3E => {
            m.mark(0xDD3E);
            m.cmp(u16, m.di, 0x47); // DD3E cmp di, 0x47
            if (m.sf != m.of) continue :sw 0xDD4E; // DD41 jl 0xdd4e
            m.cmp(u8, m.rb(m.di +% 0x9EEC), 0x1); // DD43 cmp byte ptr [di - 0x6114], 1
            if (!m.zf) continue :sw 0xDD4E; // DD48 jne 0xdd4e
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x64)); // DD4A add word ptr [bp - 2], 0x64
            continue :sw 0xDD4E; // falls through
        },
        0xDD4E => {
            m.mark(0xDD4E);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // DD4E add word ptr [bp - 2], 0xc8
            continue :sw 0xDD53; // falls through
        },
        0xDD53 => {
            m.mark(0xDD53);
            m.bx = m.rw(m.bp +% 0x000A); // DD53 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // DD56 inc byte ptr [bx]
            continue :sw 0xDD58; // falls through
        },
        0xDD58 => {
            m.mark(0xDD58);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x28)); // DD58 add word ptr [bp - 4], 0x28
            continue :sw 0xDD5C; // falls through
        },
        0xDD5C => {
            m.mark(0xDD5C);
            m.setAl(m.rb(0xA050)); // DD5C mov al, byte ptr [0xa050]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // DD5F sub ah, ah
            m.di = m.ax; // DD61 mov di, ax
            m.cmp(u16, m.di, 0x62); // DD63 cmp di, 0x62
            if (m.zf or m.sf != m.of) continue :sw 0xDD87; // DD66 jle 0xdd87
            m.cmp(u8, m.rb(0xA38F), m.ah()); // DD68 cmp byte ptr [0xa38f], ah
            if (!m.zf) continue :sw 0xDD71; // DD6C jne 0xdd71
            continue :sw 0xE16D; // DD6E jmp 0xe16d
        },
        0xDD71 => {
            m.mark(0xDD71);
            m.setAl(m.rb(0xA38F)); // DD71 mov al, byte ptr [0xa38f]
            m.cbw(); // DD74 cbw
            m.bx = m.ax; // DD75 mov bx, ax
            m.setAl(m.rb(m.bx +% 0xA04A)); // DD77 mov al, byte ptr [bx - 0x5fb6]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // DD7B sub ah, ah
            m.di = m.ax; // DD7D mov di, ax
            m.cmp(u16, m.di, 0x62); // DD7F cmp di, 0x62
            if (m.zf or m.sf != m.of) continue :sw 0xDD87; // DD82 jle 0xdd87
            continue :sw 0xE16D; // DD84 jmp 0xe16d
        },
        0xDD87 => {
            m.mark(0xDD87);
            m.wb(m.di +% 0x9EF6, 0x0); // DD87 mov byte ptr [di - 0x610a], 0
            m.ax = m.di +% 0x00B0; // DD8C lea ax, [di + 0xb0]
            m.si = m.ax; // DD90 mov si, ax
            m.cmp(u8, m.rb(m.di +% 0x0E16), 0x0); // DD92 cmp byte ptr [di + 0xe16], 0
            if (!m.zf) continue :sw 0xDDB4; // DD97 jne 0xddb4
            m.bx = m.ax; // DD99 mov bx, ax
            m.setAl(m.rb(0xA03C)); // DD9B mov al, byte ptr [0xa03c]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // DD9E sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // DDA0 sub bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), m.ah()); // DDA2 cmp byte ptr [bx + 0xab6], ah
            if (!m.zf) continue :sw 0xDDAB; // DDA6 jne 0xddab
            continue :sw 0xDE54; // DDA8 jmp 0xde54
        },
        0xDDAB => {
            m.mark(0xDDAB);
            m.cmp(u8, m.al(), 0x63); // DDAB cmp al, 0x63
            if (m.cf) continue :sw 0xDDB2; // DDAD jb 0xddb2
            continue :sw 0xDE54; // DDAF jmp 0xde54
        },
        0xDDB2 => {
            m.mark(0xDDB2);
            continue :sw 0xDDCA; // DDB2 jmp 0xddca
        },
        0xDDB4 => {
            m.mark(0xDDB4);
            m.bx = m.si; // DDB4 mov bx, si
            m.setAl(m.rb(0xA03D)); // DDB6 mov al, byte ptr [0xa03d]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // DDB9 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // DDBB sub bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), m.ah()); // DDBD cmp byte ptr [bx + 0xab6], ah
            if (!m.zf) continue :sw 0xDDC6; // DDC1 jne 0xddc6
            continue :sw 0xDE54; // DDC3 jmp 0xde54
        },
        0xDDC6 => {
            m.mark(0xDDC6);
            m.bx = m.si; // DDC6 mov bx, si
            m.bx = m.sub(u16, m.bx, m.ax); // DDC8 sub bx, ax
            continue :sw 0xDDCA; // falls through
        },
        0xDDCA => {
            m.mark(0xDDCA);
            m.setAl(m.rb(m.bx +% 0x0AB6)); // DDCA mov al, byte ptr [bx + 0xab6]
            m.cbw(); // DDCE cbw
            m.ww(m.bp +% 0xFFF6, m.ax); // DDCF mov word ptr [bp - 0xa], ax
            m.si = m.ax; // DDD2 mov si, ax
            m.si = m.add(u16, m.si, m.di); // DDD4 add si, di
            continue :sw 0xDDDB; // DDD6 jmp 0xdddb
        },
        0xDDD8 => {
            m.mark(0xDDD8);
            m.si = m.add(u16, m.si, m.rw(m.bp +% 0xFFF6)); // DDD8 add si, word ptr [bp - 0xa]
            continue :sw 0xDDDB; // falls through
        },
        0xDDDB => {
            m.mark(0xDDDB);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // DDDB cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xDDD8; // DDE0 je 0xddd8
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x3); // DDE2 cmp byte ptr [si - 0x610a], 3
            if (!m.zf) continue :sw 0xDE50; // DDE7 jne 0xde50
            m.setAl(m.rb(m.di +% 0xA164)); // DDE9 mov al, byte ptr [di - 0x5e9c]
            m.cbw(); // DDED cbw
            m.bx = m.ax; // DDEE mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // DDF0 mov al, byte ptr [bx + 0x490]
            m.cbw(); // DDF4 cbw
            m.cmp(u16, m.ax, m.rw(m.bp +% 0xFFF6)); // DDF5 cmp ax, word ptr [bp - 0xa]
            if (!m.zf) continue :sw 0xDE22; // DDF8 jne 0xde22
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x190)); // DDFA add word ptr [bp - 4], 0x190
            continue :sw 0xDDFF; // falls through
        },
        0xDDFF => {
            m.mark(0xDDFF);
            m.wb(m.di +% 0x9EF6, 0xC); // DDFF mov byte ptr [di - 0x610a], 0xc
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x1F4)); // DE04 add word ptr [bp - 2], 0x1f4
            m.ax = m.rw(0xA5EC); // DE09 mov ax, word ptr [0xa5ec]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // DE0C cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xDE14; // DE0F jl 0xde14
            continue :sw 0xF9E2; // DE11 jmp 0xf9e2
        },
        0xDE14 => {
            m.mark(0xDE14);
            m.bx = m.rw(m.bp +% 0x000A); // DE14 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // DE17 inc byte ptr [bx]
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x3E8)); // DE19 add word ptr [bp - 2], 0x3e8
            continue :sw 0xF9E2; // DE1E jmp 0xf9e2
        },
        0xDE22 => {
            m.mark(0xDE22);
            m.si = m.di; // DE22 mov si, di
            continue :sw 0xDE24; // falls through
        },
        0xDE24 => {
            m.mark(0xDE24);
            m.si = m.sub(u16, m.si, m.rw(m.bp +% 0xFFF6)); // DE24 sub si, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // DE27 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xDE24; // DE2C je 0xde24
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0xB); // DE2E cmp byte ptr [si - 0x610a], 0xb
            if (!m.zf) continue :sw 0xDE38; // DE33 jne 0xde38
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // DE35 inc word ptr [bp - 6]
            continue :sw 0xDE38; // falls through
        },
        0xDE38 => {
            m.mark(0xDE38);
            m.cmp(u16, m.rw(m.bp +% 0xFFF6), 0x0); // DE38 cmp word ptr [bp - 0xa], 0
            if (m.sf == m.of) continue :sw 0xDE4A; // DE3C jge 0xde4a
            m.setAl(m.rb(m.bp +% 0xFFF6)); // DE3E mov al, byte ptr [bp - 0xa]
            m.setAl(m.neg(u8, m.al())); // DE41 neg al
            continue :sw 0xDE43; // falls through
        },
        0xDE43 => {
            m.mark(0xDE43);
            m.wb(m.bp +% 0xFFF0, m.al()); // DE43 mov byte ptr [bp - 0x10], al
            continue :sw 0xDF75; // DE46 jmp 0xdf75
        },
        0xDE4A => {
            m.mark(0xDE4A);
            m.setAl(m.rb(m.bp +% 0xFFF6)); // DE4A mov al, byte ptr [bp - 0xa]
            continue :sw 0xDE43; // DE4D jmp 0xde43
        },
        0xDE50 => {
            m.mark(0xDE50);
            m.si = m.di +% 0x00B0; // DE50 lea si, [di + 0xb0]
            continue :sw 0xDE54; // falls through
        },
        0xDE54 => {
            m.mark(0xDE54);
            m.bx = m.si; // DE54 mov bx, si
            m.setAl(m.rb(0xA03E)); // DE56 mov al, byte ptr [0xa03e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // DE59 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // DE5B sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0BB4)); // DE5D mov al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // DE61 mov bx, si
            m.setCl(m.rb(0xA03F)); // DE63 mov cl, byte ptr [0xa03f]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // DE67 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // DE69 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // DE6B or al, byte ptr [bx + 0xbb4]
            if (!m.zf) continue :sw 0xDE74; // DE6F jne 0xde74
            continue :sw 0xDF1A; // DE71 jmp 0xdf1a
        },
        0xDE74 => {
            m.mark(0xDE74);
            m.si = m.di +% 0xFFF6; // DE74 lea si, [di - 0xa]
            continue :sw 0xDE7D; // DE77 jmp 0xde7d
        },
        0xDE7A => {
            m.mark(0xDE7A);
            m.si = m.sub(u16, m.si, 0xA); // DE7A sub si, 0xa
            continue :sw 0xDE7D; // falls through
        },
        0xDE7D => {
            m.mark(0xDE7D);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // DE7D cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xDE7A; // DE82 je 0xde7a
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x4); // DE84 cmp byte ptr [si - 0x610a], 4
            if (!m.zf) continue :sw 0xDEAE; // DE89 jne 0xdeae
            m.cmp(u8, m.rb(m.di +% 0xA164), 0x10); // DE8B cmp byte ptr [di - 0x5e9c], 0x10
            if (!m.zf) continue :sw 0xDE95; // DE90 jne 0xde95
            continue :sw 0xDDFF; // DE92 jmp 0xddff
        },
        0xDE95 => {
            m.mark(0xDE95);
            m.ax = m.rw(0xA272); // DE95 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // DE98 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xDEA7; // DE9B jg 0xdea7
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x12C)); // DE9D add word ptr [bp - 2], 0x12c
            m.bx = m.rw(m.bp +% 0x000A); // DEA2 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // DEA5 inc byte ptr [bx]
            continue :sw 0xDEA7; // falls through
        },
        0xDEA7 => {
            m.mark(0xDEA7);
            m.wb(m.bp +% 0xFFF0, 0xA); // DEA7 mov byte ptr [bp - 0x10], 0xa
            continue :sw 0xDF75; // DEAB jmp 0xdf75
        },
        0xDEAE => {
            m.mark(0xDEAE);
            m.si = m.di +% 0x0001; // DEAE lea si, [di + 1]
            continue :sw 0xDEB5; // DEB1 jmp 0xdeb5
        },
        0xDEB4 => {
            m.mark(0xDEB4);
            m.si = m.inc(u16, m.si); // DEB4 inc si
            continue :sw 0xDEB5; // falls through
        },
        0xDEB5 => {
            m.mark(0xDEB5);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // DEB5 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xDEB4; // DEBA je 0xdeb4
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x4); // DEBC cmp byte ptr [si - 0x610a], 4
            if (!m.zf) continue :sw 0xDED4; // DEC1 jne 0xded4
            m.cmp(u8, m.rb(m.di +% 0xA164), 0xD); // DEC3 cmp byte ptr [di - 0x5e9c], 0xd
            if (!m.zf) continue :sw 0xDECD; // DEC8 jne 0xdecd
            continue :sw 0xDDFF; // DECA jmp 0xddff
        },
        0xDECD => {
            m.mark(0xDECD);
            m.wb(m.bp +% 0xFFF0, 0x1); // DECD mov byte ptr [bp - 0x10], 1
            continue :sw 0xDF75; // DED1 jmp 0xdf75
        },
        0xDED4 => {
            m.mark(0xDED4);
            m.si = m.di +% 0xFFFF; // DED4 lea si, [di - 1]
            continue :sw 0xDEDB; // DED7 jmp 0xdedb
        },
        0xDEDA => {
            m.mark(0xDEDA);
            m.si = m.dec(u16, m.si); // DEDA dec si
            continue :sw 0xDEDB; // falls through
        },
        0xDEDB => {
            m.mark(0xDEDB);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // DEDB cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xDEDA; // DEE0 je 0xdeda
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x4); // DEE2 cmp byte ptr [si - 0x610a], 4
            if (!m.zf) continue :sw 0xDEF4; // DEE7 jne 0xdef4
            m.cmp(u8, m.rb(m.di +% 0xA164), 0xF); // DEE9 cmp byte ptr [di - 0x5e9c], 0xf
            if (!m.zf) continue :sw 0xDECD; // DEEE jne 0xdecd
            continue :sw 0xDDFF; // DEF0 jmp 0xddff
        },
        0xDEF4 => {
            m.mark(0xDEF4);
            m.si = m.di +% 0x000A; // DEF4 lea si, [di + 0xa]
            continue :sw 0xDEFD; // DEF7 jmp 0xdefd
        },
        0xDEFA => {
            m.mark(0xDEFA);
            m.si = m.add(u16, m.si, 0xA); // DEFA add si, 0xa
            continue :sw 0xDEFD; // falls through
        },
        0xDEFD => {
            m.mark(0xDEFD);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // DEFD cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xDEFA; // DF02 je 0xdefa
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x4); // DF04 cmp byte ptr [si - 0x610a], 4
            if (!m.zf) continue :sw 0xDF16; // DF09 jne 0xdf16
            m.cmp(u8, m.rb(m.di +% 0xA164), 0xE); // DF0B cmp byte ptr [di - 0x5e9c], 0xe
            if (!m.zf) continue :sw 0xDEA7; // DF10 jne 0xdea7
            continue :sw 0xDDFF; // DF12 jmp 0xddff
        },
        0xDF16 => {
            m.mark(0xDF16);
            m.si = m.di +% 0x00B0; // DF16 lea si, [di + 0xb0]
            continue :sw 0xDF1A; // falls through
        },
        0xDF1A => {
            m.mark(0xDF1A);
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // DF1A cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xDF4E; // DF1F je 0xdf4e
            m.ww(m.bp +% 0xFFFA, 0xD); // DF21 mov word ptr [bp - 6], 0xd
            m.ax = m.rw(0xA272); // DF26 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // DF29 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xDF48; // DF2C jg 0xdf48
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x1F4)); // DF2E add word ptr [bp - 2], 0x1f4
            m.wb(m.di +% 0x9EF6, 0xC); // DF33 mov byte ptr [di - 0x610a], 0xc
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // DF38 inc word ptr [bp - 6]
            m.bx = m.rw(m.bp +% 0x000A); // DF3B mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // DF3E inc byte ptr [bx]
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x5DC)); // DF40 add word ptr [bp - 2], 0x5dc
            continue :sw 0xF9E2; // DF45 jmp 0xf9e2
        },
        0xDF48 => {
            m.mark(0xDF48);
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // DF48 inc word ptr [bp - 6]
            continue :sw 0xDF71; // DF4B jmp 0xdf71
        },
        0xDF4E => {
            m.mark(0xDF4E);
            m.bx = m.si; // DF4E mov bx, si
            m.setAl(m.rb(0xA03B)); // DF50 mov al, byte ptr [0xa03b]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // DF53 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // DF55 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x09B8)); // DF57 mov al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // DF5B mov bx, si
            m.setCl(m.rb(0xA03A)); // DF5D mov cl, byte ptr [0xa03a]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // DF61 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // DF63 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // DF65 or al, byte ptr [bx + 0x9b8]
            if (!m.zf) continue :sw 0xDF6E; // DF69 jne 0xdf6e
            continue :sw 0xE138; // DF6B jmp 0xe138
        },
        0xDF6E => {
            m.mark(0xDF6E);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // DF6E inc word ptr [bp - 8]
            continue :sw 0xDF71; // falls through
        },
        0xDF71 => {
            m.mark(0xDF71);
            m.wb(m.bp +% 0xFFF0, 0x0); // DF71 mov byte ptr [bp - 0x10], 0
            continue :sw 0xDF75; // falls through
        },
        0xDF75 => {
            m.mark(0xDF75);
            m.cmp(u8, m.rb(m.bp +% 0xFFF0), 0x9); // DF75 cmp byte ptr [bp - 0x10], 9
            if (m.zf) continue :sw 0xDFE9; // DF79 je 0xdfe9
            m.si = m.di +% 0xFFF7; // DF7B lea si, [di - 9]
            continue :sw 0xDF7E; // falls through
        },
        0xDF7E => {
            m.mark(0xDF7E);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // DF7E cmp byte ptr [si - 0x610a], 0
            if (!m.zf) continue :sw 0xDFA8; // DF83 jne 0xdfa8
            m.push(0x1B); // DF85 push 0x1b
            m.push(m.si); // DF87 push si
            m.far(.att_4cec, 0xDF88); // DF88 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // DF8D or ax, ax
            if (m.sf != m.of) continue :sw 0xDFA2; // DF8F jl 0xdfa2
            continue :sw 0xDF91; // falls through
        },
        0xDF91 => {
            m.mark(0xDF91);
            m.cmp(u8, m.rb(m.bp +% 0xFFF0), 0x0); // DF91 cmp byte ptr [bp - 0x10], 0
            if (m.zf) continue :sw 0xDF9A; // DF95 je 0xdf9a
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // DF97 inc word ptr [bp - 8]
            continue :sw 0xDF9A; // falls through
        },
        0xDF9A => {
            m.mark(0xDF9A);
            m.wb(m.di +% 0x9EF6, 0xC); // DF9A mov byte ptr [di - 0x610a], 0xc
            continue :sw 0xE16D; // DF9F jmp 0xe16d
        },
        0xDFA2 => {
            m.mark(0xDFA2);
            m.si = m.sub(u16, m.si, 0x9); // DFA2 sub si, 9
            continue :sw 0xDF7E; // DFA5 jmp 0xdf7e
        },
        0xDFA8 => {
            m.mark(0xDFA8);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // DFA8 cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xDFBB; // DFAD jge 0xdfbb
            m.push(0x1B); // DFAF push 0x1b
            m.push(m.si); // DFB1 push si
            m.far(.att_4cec, 0xDFB2); // DFB2 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // DFB7 or ax, ax
            if (m.sf == m.of) continue :sw 0xDF91; // DFB9 jge 0xdf91
            continue :sw 0xDFBB; // falls through
        },
        0xDFBB => {
            m.mark(0xDFBB);
            m.si = m.di +% 0x0009; // DFBB lea si, [di + 9]
            continue :sw 0xDFCF; // DFBE jmp 0xdfcf
        },
        0xDFC0 => {
            m.mark(0xDFC0);
            m.push(0x1B); // DFC0 push 0x1b
            m.push(m.si); // DFC2 push si
            m.far(.att_4cec, 0xDFC3); // DFC3 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // DFC8 or ax, ax
            if (m.sf == m.of) continue :sw 0xDF91; // DFCA jge 0xdf91
            m.si = m.add(u16, m.si, 0x9); // DFCC add si, 9
            continue :sw 0xDFCF; // falls through
        },
        0xDFCF => {
            m.mark(0xDFCF);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // DFCF cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xDFC0; // DFD4 je 0xdfc0
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // DFD6 cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xDFE9; // DFDB jge 0xdfe9
            m.push(0x1B); // DFDD push 0x1b
            m.push(m.si); // DFDF push si
            m.far(.att_4cec, 0xDFE0); // DFE0 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // DFE5 or ax, ax
            if (m.sf == m.of) continue :sw 0xDF91; // DFE7 jge 0xdf91
            continue :sw 0xDFE9; // falls through
        },
        0xDFE9 => {
            m.mark(0xDFE9);
            m.cmp(u8, m.rb(m.bp +% 0xFFF0), 0xB); // DFE9 cmp byte ptr [bp - 0x10], 0xb
            if (m.zf) continue :sw 0xE055; // DFED je 0xe055
            m.si = m.di +% 0xFFF5; // DFEF lea si, [di - 0xb]
            continue :sw 0xE003; // DFF2 jmp 0xe003
        },
        0xDFF4 => {
            m.mark(0xDFF4);
            m.push(0x1B); // DFF4 push 0x1b
            m.push(m.si); // DFF6 push si
            m.far(.att_4cec, 0xDFF7); // DFF7 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // DFFC or ax, ax
            if (m.sf == m.of) continue :sw 0xDF91; // DFFE jge 0xdf91
            m.si = m.sub(u16, m.si, 0xB); // E000 sub si, 0xb
            continue :sw 0xE003; // falls through
        },
        0xE003 => {
            m.mark(0xE003);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E003 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xDFF4; // E008 je 0xdff4
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // E00A cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xE020; // E00F jge 0xe020
            m.push(0x1B); // E011 push 0x1b
            m.push(m.si); // E013 push si
            m.far(.att_4cec, 0xE014); // E014 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E019 or ax, ax
            if (m.sf != m.of) continue :sw 0xE020; // E01B jl 0xe020
            continue :sw 0xDF91; // E01D jmp 0xdf91
        },
        0xE020 => {
            m.mark(0xE020);
            m.si = m.di +% 0x000B; // E020 lea si, [di + 0xb]
            continue :sw 0xE038; // E023 jmp 0xe038
        },
        0xE026 => {
            m.mark(0xE026);
            m.push(0x1B); // E026 push 0x1b
            m.push(m.si); // E028 push si
            m.far(.att_4cec, 0xE029); // E029 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E02E or ax, ax
            if (m.sf != m.of) continue :sw 0xE035; // E030 jl 0xe035
            continue :sw 0xDF91; // E032 jmp 0xdf91
        },
        0xE035 => {
            m.mark(0xE035);
            m.si = m.add(u16, m.si, 0xB); // E035 add si, 0xb
            continue :sw 0xE038; // falls through
        },
        0xE038 => {
            m.mark(0xE038);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E038 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE026; // E03D je 0xe026
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // E03F cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xE055; // E044 jge 0xe055
            m.push(0x1B); // E046 push 0x1b
            m.push(m.si); // E048 push si
            m.far(.att_4cec, 0xE049); // E049 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E04E or ax, ax
            if (m.sf != m.of) continue :sw 0xE055; // E050 jl 0xe055
            continue :sw 0xDF91; // E052 jmp 0xdf91
        },
        0xE055 => {
            m.mark(0xE055);
            m.cmp(u8, m.rb(m.bp +% 0xFFF0), 0x1); // E055 cmp byte ptr [bp - 0x10], 1
            if (m.zf) continue :sw 0xE0BF; // E059 je 0xe0bf
            m.si = m.di +% 0x0001; // E05B lea si, [di + 1]
            continue :sw 0xE070; // E05E jmp 0xe070
        },
        0xE060 => {
            m.mark(0xE060);
            m.push(0x1B); // E060 push 0x1b
            m.push(m.si); // E062 push si
            m.far(.att_4cec, 0xE063); // E063 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E068 or ax, ax
            if (m.sf != m.of) continue :sw 0xE06F; // E06A jl 0xe06f
            continue :sw 0xDF91; // E06C jmp 0xdf91
        },
        0xE06F => {
            m.mark(0xE06F);
            m.si = m.inc(u16, m.si); // E06F inc si
            continue :sw 0xE070; // falls through
        },
        0xE070 => {
            m.mark(0xE070);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E070 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE060; // E075 je 0xe060
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // E077 cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xE08D; // E07C jge 0xe08d
            m.push(0x1B); // E07E push 0x1b
            m.push(m.si); // E080 push si
            m.far(.att_4cec, 0xE081); // E081 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E086 or ax, ax
            if (m.sf != m.of) continue :sw 0xE08D; // E088 jl 0xe08d
            continue :sw 0xDF91; // E08A jmp 0xdf91
        },
        0xE08D => {
            m.mark(0xE08D);
            m.si = m.di +% 0xFFFF; // E08D lea si, [di - 1]
            continue :sw 0xE0A2; // E090 jmp 0xe0a2
        },
        0xE092 => {
            m.mark(0xE092);
            m.push(0x1B); // E092 push 0x1b
            m.push(m.si); // E094 push si
            m.far(.att_4cec, 0xE095); // E095 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E09A or ax, ax
            if (m.sf != m.of) continue :sw 0xE0A1; // E09C jl 0xe0a1
            continue :sw 0xDF91; // E09E jmp 0xdf91
        },
        0xE0A1 => {
            m.mark(0xE0A1);
            m.si = m.dec(u16, m.si); // E0A1 dec si
            continue :sw 0xE0A2; // falls through
        },
        0xE0A2 => {
            m.mark(0xE0A2);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E0A2 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE092; // E0A7 je 0xe092
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // E0A9 cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xE0BF; // E0AE jge 0xe0bf
            m.push(0x1B); // E0B0 push 0x1b
            m.push(m.si); // E0B2 push si
            m.far(.att_4cec, 0xE0B3); // E0B3 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E0B8 or ax, ax
            if (m.sf != m.of) continue :sw 0xE0BF; // E0BA jl 0xe0bf
            continue :sw 0xDF91; // E0BC jmp 0xdf91
        },
        0xE0BF => {
            m.mark(0xE0BF);
            m.cmp(u8, m.rb(m.bp +% 0xFFF0), 0xA); // E0BF cmp byte ptr [bp - 0x10], 0xa
            if (!m.zf) continue :sw 0xE0C8; // E0C3 jne 0xe0c8
            continue :sw 0xDDFF; // E0C5 jmp 0xddff
        },
        0xE0C8 => {
            m.mark(0xE0C8);
            m.si = m.di +% 0x000A; // E0C8 lea si, [di + 0xa]
            continue :sw 0xE0E0; // E0CB jmp 0xe0e0
        },
        0xE0CE => {
            m.mark(0xE0CE);
            m.push(0x1B); // E0CE push 0x1b
            m.push(m.si); // E0D0 push si
            m.far(.att_4cec, 0xE0D1); // E0D1 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E0D6 or ax, ax
            if (m.sf != m.of) continue :sw 0xE0DD; // E0D8 jl 0xe0dd
            continue :sw 0xDF91; // E0DA jmp 0xdf91
        },
        0xE0DD => {
            m.mark(0xE0DD);
            m.si = m.add(u16, m.si, 0xA); // E0DD add si, 0xa
            continue :sw 0xE0E0; // falls through
        },
        0xE0E0 => {
            m.mark(0xE0E0);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E0E0 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE0CE; // E0E5 je 0xe0ce
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // E0E7 cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xE0FD; // E0EC jge 0xe0fd
            m.push(0x1B); // E0EE push 0x1b
            m.push(m.si); // E0F0 push si
            m.far(.att_4cec, 0xE0F1); // E0F1 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E0F6 or ax, ax
            if (m.sf != m.of) continue :sw 0xE0FD; // E0F8 jl 0xe0fd
            continue :sw 0xDF91; // E0FA jmp 0xdf91
        },
        0xE0FD => {
            m.mark(0xE0FD);
            m.si = m.di +% 0xFFF6; // E0FD lea si, [di - 0xa]
            continue :sw 0xE114; // E100 jmp 0xe114
        },
        0xE102 => {
            m.mark(0xE102);
            m.push(0x1B); // E102 push 0x1b
            m.push(m.si); // E104 push si
            m.far(.att_4cec, 0xE105); // E105 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E10A or ax, ax
            if (m.sf != m.of) continue :sw 0xE111; // E10C jl 0xe111
            continue :sw 0xDF91; // E10E jmp 0xdf91
        },
        0xE111 => {
            m.mark(0xE111);
            m.si = m.sub(u16, m.si, 0xA); // E111 sub si, 0xa
            continue :sw 0xE114; // falls through
        },
        0xE114 => {
            m.mark(0xE114);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E114 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE102; // E119 je 0xe102
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // E11B cmp byte ptr [si - 0x610a], 7
            if (m.sf != m.of) continue :sw 0xE125; // E120 jl 0xe125
            continue :sw 0xDDFF; // E122 jmp 0xddff
        },
        0xE125 => {
            m.mark(0xE125);
            m.push(0x1B); // E125 push 0x1b
            m.push(m.si); // E127 push si
            m.far(.att_4cec, 0xE128); // E128 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E12D or ax, ax
            if (m.sf != m.of) continue :sw 0xE134; // E12F jl 0xe134
            continue :sw 0xDF91; // E131 jmp 0xdf91
        },
        0xE134 => {
            m.mark(0xE134);
            continue :sw 0xDDFF; // E134 jmp 0xddff
        },
        0xE138 => {
            m.mark(0xE138);
            m.wb(m.di +% 0x9EF6, 0xC); // E138 mov byte ptr [di - 0x610a], 0xc
            m.bx = m.si; // E13D mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // E13F sub bx, word ptr [bp - 0xc]
            m.setAl(m.rb(m.bx +% 0x0BB4)); // E142 mov al, byte ptr [bx + 0xbb4]
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // E146 or al, byte ptr [bx + 0xab6]
            if (m.zf) continue :sw 0xE16D; // E14A je 0xe16d
            m.push(0x36); // E14C push 0x36
            m.push(m.di); // E14E push di
            m.far(.att_4cec, 0xE14F); // E14F lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E154 or ax, ax
            if (m.sf == m.of) continue :sw 0xE16D; // E156 jge 0xe16d
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // E158 inc word ptr [bp - 8]
            m.ax = m.rw(0xA272); // E15B mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // E15E cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xE16D; // E161 jg 0xe16d
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x12C)); // E163 add word ptr [bp - 2], 0x12c
            m.bx = m.rw(m.bp +% 0x000A); // E168 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // E16B inc byte ptr [bx]
            continue :sw 0xE16D; // falls through
        },
        0xE16D => {
            m.mark(0xE16D);
            m.setAl(m.rb(0xA04F)); // E16D mov al, byte ptr [0xa04f]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // E170 sub ah, ah
            m.di = m.ax; // E172 mov di, ax
            m.cmp(u16, m.di, 0x62); // E174 cmp di, 0x62
            if (m.zf or m.sf != m.of) continue :sw 0xE17C; // E177 jle 0xe17c
            continue :sw 0xE5ED; // E179 jmp 0xe5ed
        },
        0xE17C => {
            m.mark(0xE17C);
            m.cmp(u8, m.rb(m.di +% 0xA164), 0x9); // E17C cmp byte ptr [di - 0x5e9c], 9
            if (m.sf == m.of) continue :sw 0xE186; // E181 jge 0xe186
            continue :sw 0xE302; // E183 jmp 0xe302
        },
        0xE186 => {
            m.mark(0xE186);
            m.cmp(u8, m.rb(m.di +% 0xA164), 0xC); // E186 cmp byte ptr [di - 0x5e9c], 0xc
            if (m.zf or m.sf != m.of) continue :sw 0xE190; // E18B jle 0xe190
            continue :sw 0xE302; // E18D jmp 0xe302
        },
        0xE190 => {
            m.mark(0xE190);
            m.setAl(m.rb(m.di +% 0xA164)); // E190 mov al, byte ptr [di - 0x5e9c]
            m.cbw(); // E194 cbw
            m.bx = m.ax; // E195 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // E197 mov al, byte ptr [bx + 0x490]
            m.cbw(); // E19B cbw
            m.si = m.ax; // E19C mov si, ax
            continue :sw 0xE19E; // falls through
        },
        0xE19E => {
            m.mark(0xE19E);
            m.di = m.add(u16, m.di, m.si); // E19E add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // E1A0 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xE19E; // E1A5 je 0xe19e
            m.si = m.di; // E1A7 mov si, di
            m.setAl(m.rb(0xA04F)); // E1A9 mov al, byte ptr [0xa04f]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // E1AC sub ah, ah
            m.di = m.ax; // E1AE mov di, ax
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x3); // E1B0 cmp byte ptr [si - 0x610a], 3
            if (!m.zf) continue :sw 0xE1E6; // E1B5 jne 0xe1e6
            m.ax = m.rw(0x9356); // E1B7 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // E1BA cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xE1D4; // E1BD jge 0xe1d4
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x514)); // E1BF add word ptr [bp - 2], 0x514
            m.bx = m.rw(m.bp +% 0x000A); // E1C4 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // E1C7 inc byte ptr [bx]
            continue :sw 0xE1C9; // falls through
        },
        0xE1C9 => {
            m.mark(0xE1C9);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x12C)); // E1C9 add word ptr [bp - 4], 0x12c
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // E1CE inc word ptr [bp - 6]
            continue :sw 0xE5ED; // E1D1 jmp 0xe5ed
        },
        0xE1D4 => {
            m.mark(0xE1D4);
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // E1D4 cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xE1C9; // E1D9 je 0xe1c9
            continue :sw 0xE1DB; // falls through
        },
        0xE1DB => {
            m.mark(0xE1DB);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x320)); // E1DB add word ptr [bp - 2], 0x320
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // E1E0 inc word ptr [bp - 8]
            continue :sw 0xF9E2; // E1E3 jmp 0xf9e2
        },
        0xE1E6 => {
            m.mark(0xE1E6);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x5); // E1E6 cmp byte ptr [si - 0x610a], 5
            if (m.zf) continue :sw 0xE1F0; // E1EB je 0xe1f0
            continue :sw 0xE302; // E1ED jmp 0xe302
        },
        0xE1F0 => {
            m.mark(0xE1F0);
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // E1F0 cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xE212; // E1F5 je 0xe212
            continue :sw 0xE1F7; // falls through
        },
        0xE1F7 => {
            m.mark(0xE1F7);
            m.ax = m.rw(0x9356); // E1F7 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // E1FA cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xE209; // E1FD jge 0xe209
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x190)); // E1FF add word ptr [bp - 2], 0x190
            m.bx = m.rw(m.bp +% 0x000A); // E204 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // E207 inc byte ptr [bx]
            continue :sw 0xE209; // falls through
        },
        0xE209 => {
            m.mark(0xE209);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x320)); // E209 add word ptr [bp - 2], 0x320
            continue :sw 0xF9E2; // E20E jmp 0xf9e2
        },
        0xE212 => {
            m.mark(0xE212);
            m.si = m.di +% 0x00B0; // E212 lea si, [di + 0xb0]
            m.bx = m.si; // E216 mov bx, si
            m.setAl(m.rb(0xA03B)); // E218 mov al, byte ptr [0xa03b]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // E21B sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // E21D sub bx, ax
            m.setAl(m.rb(m.bx +% 0x09B8)); // E21F mov al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // E223 mov bx, si
            m.setCl(m.rb(0xA03A)); // E225 mov cl, byte ptr [0xa03a]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // E229 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // E22B sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // E22D or al, byte ptr [bx + 0x9b8]
            if (m.zf) continue :sw 0xE250; // E231 je 0xe250
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x15E)); // E233 add word ptr [bp - 4], 0x15e
            m.ax = m.rw(0x9356); // E238 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // E23B cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xE243; // E23E jl 0xe243
            continue :sw 0xE5ED; // E240 jmp 0xe5ed
        },
        0xE243 => {
            m.mark(0xE243);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x320)); // E243 add word ptr [bp - 2], 0x320
            continue :sw 0xE248; // falls through
        },
        0xE248 => {
            m.mark(0xE248);
            m.bx = m.rw(m.bp +% 0x000A); // E248 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // E24B inc byte ptr [bx]
            continue :sw 0xE5ED; // E24D jmp 0xe5ed
        },
        0xE250 => {
            m.mark(0xE250);
            m.cmp(u8, m.rb(m.di +% 0xA164), 0x9); // E250 cmp byte ptr [di - 0x5e9c], 9
            if (m.zf) continue :sw 0xE25E; // E255 je 0xe25e
            m.cmp(u8, m.rb(m.di +% 0xA164), 0xB); // E257 cmp byte ptr [di - 0x5e9c], 0xb
            if (!m.zf) continue :sw 0xE2B2; // E25C jne 0xe2b2
            continue :sw 0xE25E; // falls through
        },
        0xE25E => {
            m.mark(0xE25E);
            m.si = m.di +% 0x000B; // E25E lea si, [di + 0xb]
            continue :sw 0xE267; // E261 jmp 0xe267
        },
        0xE264 => {
            m.mark(0xE264);
            m.si = m.add(u16, m.si, 0xB); // E264 add si, 0xb
            continue :sw 0xE267; // falls through
        },
        0xE267 => {
            m.mark(0xE267);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E267 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE264; // E26C je 0xe264
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x3); // E26E cmp byte ptr [si - 0x610a], 3
            if (!m.zf) continue :sw 0xE294; // E273 jne 0xe294
            m.ax = m.si; // E275 mov ax, si
            m.ax = m.sub(u16, m.ax, m.di); // E277 sub ax, di
            continue :sw 0xE279; // falls through
        },
        0xE279 => {
            m.mark(0xE279);
            m.cmp(u16, m.ax, 0xB); // E279 cmp ax, 0xb
            continue :sw 0xE27C; // falls through
        },
        0xE27C => {
            m.mark(0xE27C);
            if (!m.zf) continue :sw 0xE283; // E27C jne 0xe283
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x12C)); // E27E add word ptr [bp - 4], 0x12c
            continue :sw 0xE283; // falls through
        },
        0xE283 => {
            m.mark(0xE283);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0xC8)); // E283 add word ptr [bp - 4], 0xc8
            m.ax = m.rw(0x9356); // E288 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // E28B cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xE30D; // E28E jge 0xe30d
            continue :sw 0xE48A; // E290 jmp 0xe48a
        },
        0xE294 => {
            m.mark(0xE294);
            m.si = m.di +% 0xFFF5; // E294 lea si, [di - 0xb]
            continue :sw 0xE29D; // E297 jmp 0xe29d
        },
        0xE29A => {
            m.mark(0xE29A);
            m.si = m.sub(u16, m.si, 0xB); // E29A sub si, 0xb
            continue :sw 0xE29D; // falls through
        },
        0xE29D => {
            m.mark(0xE29D);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E29D cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE29A; // E2A2 je 0xe29a
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x3); // E2A4 cmp byte ptr [si - 0x610a], 3
            if (!m.zf) continue :sw 0xE2F0; // E2A9 jne 0xe2f0
            m.ax = m.di; // E2AB mov ax, di
            m.ax = m.sub(u16, m.ax, m.si); // E2AD sub ax, si
            continue :sw 0xE279; // E2AF jmp 0xe279
        },
        0xE2B2 => {
            m.mark(0xE2B2);
            m.si = m.di +% 0x0009; // E2B2 lea si, [di + 9]
            continue :sw 0xE2BB; // E2B5 jmp 0xe2bb
        },
        0xE2B8 => {
            m.mark(0xE2B8);
            m.si = m.add(u16, m.si, 0x9); // E2B8 add si, 9
            continue :sw 0xE2BB; // falls through
        },
        0xE2BB => {
            m.mark(0xE2BB);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E2BB cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE2B8; // E2C0 je 0xe2b8
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x3); // E2C2 cmp byte ptr [si - 0x610a], 3
            if (!m.zf) continue :sw 0xE2D0; // E2C7 jne 0xe2d0
            m.ax = m.si; // E2C9 mov ax, si
            m.ax = m.sub(u16, m.ax, m.di); // E2CB sub ax, di
            continue :sw 0xE2EB; // E2CD jmp 0xe2eb
        },
        0xE2D0 => {
            m.mark(0xE2D0);
            m.si = m.di +% 0xFFF7; // E2D0 lea si, [di - 9]
            continue :sw 0xE2D9; // E2D3 jmp 0xe2d9
        },
        0xE2D6 => {
            m.mark(0xE2D6);
            m.si = m.sub(u16, m.si, 0x9); // E2D6 sub si, 9
            continue :sw 0xE2D9; // falls through
        },
        0xE2D9 => {
            m.mark(0xE2D9);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E2D9 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE2D6; // E2DE je 0xe2d6
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x3); // E2E0 cmp byte ptr [si - 0x610a], 3
            if (!m.zf) continue :sw 0xE2F0; // E2E5 jne 0xe2f0
            m.ax = m.di; // E2E7 mov ax, di
            m.ax = m.sub(u16, m.ax, m.si); // E2E9 sub ax, si
            continue :sw 0xE2EB; // falls through
        },
        0xE2EB => {
            m.mark(0xE2EB);
            m.cmp(u16, m.ax, 0x9); // E2EB cmp ax, 9
            continue :sw 0xE27C; // E2EE jmp 0xe27c
        },
        0xE2F0 => {
            m.mark(0xE2F0);
            m.push(0x1E); // E2F0 push 0x1e
            m.push(m.di); // E2F2 push di
            m.far(.att_4cec, 0xE2F3); // E2F3 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E2F8 or ax, ax
            if (m.sf != m.of) continue :sw 0xE2FF; // E2FA jl 0xe2ff
            continue :sw 0xE5ED; // E2FC jmp 0xe5ed
        },
        0xE2FF => {
            m.mark(0xE2FF);
            continue :sw 0xE283; // E2FF jmp 0xe283
        },
        0xE302 => {
            m.mark(0xE302);
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // E302 cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xE348; // E307 je 0xe348
            m.ww(m.bp +% 0xFFFA, m.add(u16, m.rw(m.bp +% 0xFFFA), 0xD)); // E309 add word ptr [bp - 6], 0xd
            continue :sw 0xE30D; // falls through
        },
        0xE30D => {
            m.mark(0xE30D);
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // E30D inc word ptr [bp - 6]
            continue :sw 0xE310; // falls through
        },
        0xE310 => {
            m.mark(0xE310);
            m.cmp(u16, m.di, 0x5B); // E310 cmp di, 0x5b
            if (m.sf == m.of) continue :sw 0xE318; // E313 jge 0xe318
            continue :sw 0xE4F3; // E315 jmp 0xe4f3
        },
        0xE318 => {
            m.mark(0xE318);
            m.cmp(u8, m.rb(m.di +% 0x9EEC), 0x0); // E318 cmp byte ptr [di - 0x6114], 0
            if (!m.zf) continue :sw 0xE322; // E31D jne 0xe322
            continue :sw 0xE4F3; // E31F jmp 0xe4f3
        },
        0xE322 => {
            m.mark(0xE322);
            m.cmp(u8, m.rb(m.di +% 0x9EEC), 0x1); // E322 cmp byte ptr [di - 0x6114], 1
            if (m.zf) continue :sw 0xE32C; // E327 je 0xe32c
            continue :sw 0xE4DA; // E329 jmp 0xe4da
        },
        0xE32C => {
            m.mark(0xE32C);
            m.ax = m.rw(0x9356); // E32C mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // E32F cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xE337; // E332 jge 0xe337
            continue :sw 0xE48A; // E334 jmp 0xe48a
        },
        0xE337 => {
            m.mark(0xE337);
            m.cmp(u16, m.rw(m.bp +% 0xFFFA), 0x0); // E337 cmp word ptr [bp - 6], 0
            if (!m.zf) continue :sw 0xE340; // E33B jne 0xe340
            continue :sw 0xE4F3; // E33D jmp 0xe4f3
        },
        0xE340 => {
            m.mark(0xE340);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0xC8)); // E340 add word ptr [bp - 4], 0xc8
            continue :sw 0xE4F3; // E345 jmp 0xe4f3
        },
        0xE348 => {
            m.mark(0xE348);
            m.si = m.di +% 0x00B0; // E348 lea si, [di + 0xb0]
            m.bx = m.si; // E34C mov bx, si
            m.setAl(m.rb(0xA03B)); // E34E mov al, byte ptr [0xa03b]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // E351 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // E353 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x09B8)); // E355 mov al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // E359 mov bx, si
            m.setCl(m.rb(0xA03A)); // E35B mov cl, byte ptr [0xa03a]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // E35F sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // E361 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // E363 or al, byte ptr [bx + 0x9b8]
            if (!m.zf) continue :sw 0xE30D; // E367 jne 0xe30d
            m.cmp(u8, m.rb(m.di +% 0x0E16), m.ah()); // E369 cmp byte ptr [di + 0xe16], ah
            if (!m.zf) continue :sw 0xE38A; // E36D jne 0xe38a
            m.bx = m.si; // E36F mov bx, si
            m.setAl(m.rb(0xA03C)); // E371 mov al, byte ptr [0xa03c]
            m.bx = m.sub(u16, m.bx, m.ax); // E374 sub bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), m.ah()); // E376 cmp byte ptr [bx + 0xab6], ah
            if (!m.zf) continue :sw 0xE37F; // E37A jne 0xe37f
            continue :sw 0xE424; // E37C jmp 0xe424
        },
        0xE37F => {
            m.mark(0xE37F);
            m.cmp(u8, m.al(), 0x63); // E37F cmp al, 0x63
            if (m.cf) continue :sw 0xE386; // E381 jb 0xe386
            continue :sw 0xE424; // E383 jmp 0xe424
        },
        0xE386 => {
            m.mark(0xE386);
            continue :sw 0xE3A0; // E386 jmp 0xe3a0
        },
        0xE38A => {
            m.mark(0xE38A);
            m.bx = m.si; // E38A mov bx, si
            m.setAl(m.rb(0xA03D)); // E38C mov al, byte ptr [0xa03d]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // E38F sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // E391 sub bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), m.ah()); // E393 cmp byte ptr [bx + 0xab6], ah
            if (!m.zf) continue :sw 0xE39C; // E397 jne 0xe39c
            continue :sw 0xE424; // E399 jmp 0xe424
        },
        0xE39C => {
            m.mark(0xE39C);
            m.bx = m.si; // E39C mov bx, si
            m.bx = m.sub(u16, m.bx, m.ax); // E39E sub bx, ax
            continue :sw 0xE3A0; // falls through
        },
        0xE3A0 => {
            m.mark(0xE3A0);
            m.setAl(m.rb(m.bx +% 0x0AB6)); // E3A0 mov al, byte ptr [bx + 0xab6]
            m.cbw(); // E3A4 cbw
            m.ww(m.bp +% 0xFFF6, m.ax); // E3A5 mov word ptr [bp - 0xa], ax
            m.si = m.ax; // E3A8 mov si, ax
            m.si = m.add(u16, m.si, m.di); // E3AA add si, di
            continue :sw 0xE3B3; // E3AC jmp 0xe3b3
        },
        0xE3B0 => {
            m.mark(0xE3B0);
            m.si = m.add(u16, m.si, m.rw(m.bp +% 0xFFF6)); // E3B0 add si, word ptr [bp - 0xa]
            continue :sw 0xE3B3; // falls through
        },
        0xE3B3 => {
            m.mark(0xE3B3);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E3B3 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE3B0; // E3B8 je 0xe3b0
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x3); // E3BA cmp byte ptr [si - 0x610a], 3
            if (!m.zf) continue :sw 0xE420; // E3BF jne 0xe420
            m.ax = m.si; // E3C1 mov ax, si
            m.ax = m.sub(u16, m.ax, m.rw(m.bp +% 0xFFF6)); // E3C3 sub ax, word ptr [bp - 0xa]
            m.cmp(u16, m.ax, m.di); // E3C6 cmp ax, di
            if (!m.zf) continue :sw 0xE3EC; // E3C8 jne 0xe3ec
            m.si = m.di; // E3CA mov si, di
            continue :sw 0xE3CC; // falls through
        },
        0xE3CC => {
            m.mark(0xE3CC);
            m.si = m.sub(u16, m.si, m.rw(m.bp +% 0xFFF6)); // E3CC sub si, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E3CF cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE3CC; // E3D4 je 0xe3cc
            m.setAl(m.rb(m.si +% 0x9EF6)); // E3D6 mov al, byte ptr [si - 0x610a]
            m.cbw(); // E3DA cbw
            m.bx = m.ax; // E3DB mov bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x127E), 0x0); // E3DD cmp byte ptr [bx + 0x127e], 0
            if (m.zf) continue :sw 0xE409; // E3E2 je 0xe409
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0xC8)); // E3E4 add word ptr [bp - 4], 0xc8
            continue :sw 0xE283; // E3E9 jmp 0xe283
        },
        0xE3EC => {
            m.mark(0xE3EC);
            m.si = m.di; // E3EC mov si, di
            continue :sw 0xE3EE; // falls through
        },
        0xE3EE => {
            m.mark(0xE3EE);
            m.si = m.sub(u16, m.si, m.rw(m.bp +% 0xFFF6)); // E3EE sub si, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E3F1 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE3EE; // E3F6 je 0xe3ee
            m.setAl(m.rb(m.si +% 0x9EF6)); // E3F8 mov al, byte ptr [si - 0x610a]
            m.cbw(); // E3FC cbw
            m.bx = m.ax; // E3FD mov bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x127E), 0x0); // E3FF cmp byte ptr [bx + 0x127e], 0
            if (m.zf) continue :sw 0xE409; // E404 je 0xe409
            continue :sw 0xE283; // E406 jmp 0xe283
        },
        0xE409 => {
            m.mark(0xE409);
            m.ax = m.rw(0xA272); // E409 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // E40C cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xE414; // E40F jle 0xe414
            continue :sw 0xE30D; // E411 jmp 0xe30d
        },
        0xE414 => {
            m.mark(0xE414);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x64)); // E414 add word ptr [bp - 2], 0x64
            m.bx = m.rw(m.bp +% 0x000A); // E418 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // E41B inc byte ptr [bx]
            continue :sw 0xE30D; // E41D jmp 0xe30d
        },
        0xE420 => {
            m.mark(0xE420);
            m.si = m.di +% 0x00B0; // E420 lea si, [di + 0xb0]
            continue :sw 0xE424; // falls through
        },
        0xE424 => {
            m.mark(0xE424);
            m.bx = m.si; // E424 mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // E426 sub bx, word ptr [bp - 0xc]
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), 0x0); // E429 cmp byte ptr [bx + 0xab6], 0
            if (m.zf) continue :sw 0xE468; // E42E je 0xe468
            m.setAl(m.rb(m.bx +% 0x0AB6)); // E430 mov al, byte ptr [bx + 0xab6]
            m.cbw(); // E434 cbw
            m.ww(m.bp +% 0xFFF6, m.ax); // E435 mov word ptr [bp - 0xa], ax
            m.ax = m.add(u16, m.ax, m.di); // E438 add ax, di
            m.si = m.ax; // E43A mov si, ax
            continue :sw 0xE441; // E43C jmp 0xe441
        },
        0xE43E => {
            m.mark(0xE43E);
            m.si = m.add(u16, m.si, m.rw(m.bp +% 0xFFF6)); // E43E add si, word ptr [bp - 0xa]
            continue :sw 0xE441; // falls through
        },
        0xE441 => {
            m.mark(0xE441);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E441 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE43E; // E446 je 0xe43e
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x5); // E448 cmp byte ptr [si - 0x610a], 5
            if (!m.zf) continue :sw 0xE464; // E44D jne 0xe464
            m.push(0x1E); // E44F push 0x1e
            m.push(m.di); // E451 push di
            m.far(.att_4cec, 0xE452); // E452 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E457 or ax, ax
            if (m.sf != m.of) continue :sw 0xE45E; // E459 jl 0xe45e
            continue :sw 0xE5ED; // E45B jmp 0xe5ed
        },
        0xE45E => {
            m.mark(0xE45E);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // E45E inc word ptr [bp - 8]
            continue :sw 0xE310; // E461 jmp 0xe310
        },
        0xE464 => {
            m.mark(0xE464);
            m.si = m.di +% 0x00B0; // E464 lea si, [di + 0xb0]
            continue :sw 0xE468; // falls through
        },
        0xE468 => {
            m.mark(0xE468);
            m.bx = m.di; // E468 mov bx, di
            m.setAl(m.rb(0xA041)); // E46A mov al, byte ptr [0xa041]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // E46D sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // E46F sub bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x0CFF), m.ah()); // E471 cmp byte ptr [bx + 0xcff], ah
            if (m.zf) continue :sw 0xE492; // E475 je 0xe492
            m.push(0x1E); // E477 push 0x1e
            m.push(m.di); // E479 push di
            m.far(.att_4cec, 0xE47A); // E47A lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E47F or ax, ax
            if (m.sf == m.of) continue :sw 0xE492; // E481 jge 0xe492
            m.cmp(u8, m.rb(0xA5F5), 0x0); // E483 cmp byte ptr [0xa5f5], 0
            if (m.zf) continue :sw 0xE45E; // E488 je 0xe45e
            continue :sw 0xE48A; // falls through
        },
        0xE48A => {
            m.mark(0xE48A);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x2BC)); // E48A add word ptr [bp - 2], 0x2bc
            continue :sw 0xE248; // E48F jmp 0xe248
        },
        0xE492 => {
            m.mark(0xE492);
            m.bx = m.si; // E492 mov bx, si
            m.setAl(m.rb(0xA03E)); // E494 mov al, byte ptr [0xa03e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // E497 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // E499 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0BB4)); // E49B mov al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // E49F mov bx, si
            m.setCl(m.rb(0xA03F)); // E4A1 mov cl, byte ptr [0xa03f]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // E4A5 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // E4A7 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // E4A9 or al, byte ptr [bx + 0xbb4]
            m.@"test"(u8, m.al(), 0x1); // E4AD test al, 1
            if (!m.zf) continue :sw 0xE4B4; // E4AF jne 0xe4b4
            continue :sw 0xE5ED; // E4B1 jmp 0xe5ed
        },
        0xE4B4 => {
            m.mark(0xE4B4);
            m.push(0x1E); // E4B4 push 0x1e
            m.push(m.di); // E4B6 push di
            m.far(.att_4cec, 0xE4B7); // E4B7 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E4BC or ax, ax
            if (m.sf != m.of) continue :sw 0xE4C3; // E4BE jl 0xe4c3
            continue :sw 0xE5ED; // E4C0 jmp 0xe5ed
        },
        0xE4C3 => {
            m.mark(0xE4C3);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // E4C3 inc word ptr [bp - 8]
            m.ax = m.rw(0xA272); // E4C6 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // E4C9 cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xE4D1; // E4CC jle 0xe4d1
            continue :sw 0xE5ED; // E4CE jmp 0xe5ed
        },
        0xE4D1 => {
            m.mark(0xE4D1);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xFA)); // E4D1 add word ptr [bp - 2], 0xfa
            continue :sw 0xE248; // E4D6 jmp 0xe248
        },
        0xE4DA => {
            m.mark(0xE4DA);
            m.cmp(u8, m.rb(m.di +% 0x9EEC), 0x7); // E4DA cmp byte ptr [di - 0x6114], 7
            if (m.zf or m.sf != m.of) continue :sw 0xE4F3; // E4DF jle 0xe4f3
            m.ax = m.rw(0xA272); // E4E1 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // E4E4 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xE4F3; // E4E7 jg 0xe4f3
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x12C)); // E4E9 add word ptr [bp - 2], 0x12c
            m.bx = m.rw(m.bp +% 0x000A); // E4EE mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // E4F1 inc byte ptr [bx]
            continue :sw 0xE4F3; // falls through
        },
        0xE4F3 => {
            m.mark(0xE4F3);
            m.wb(m.di +% 0x9EF6, 0x0); // E4F3 mov byte ptr [di - 0x610a], 0
            m.si = m.di +% 0x000A; // E4F8 lea si, [di + 0xa]
            continue :sw 0xE510; // E4FB jmp 0xe510
        },
        0xE4FE => {
            m.mark(0xE4FE);
            m.push(0xF); // E4FE push 0xf
            m.push(m.si); // E500 push si
            m.far(.att_4cec, 0xE501); // E501 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E506 or ax, ax
            if (m.sf != m.of) continue :sw 0xE50D; // E508 jl 0xe50d
            continue :sw 0xE5E8; // E50A jmp 0xe5e8
        },
        0xE50D => {
            m.mark(0xE50D);
            m.si = m.add(u16, m.si, 0xA); // E50D add si, 0xa
            continue :sw 0xE510; // falls through
        },
        0xE510 => {
            m.mark(0xE510);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E510 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE4FE; // E515 je 0xe4fe
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // E517 cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xE52D; // E51C jge 0xe52d
            m.push(0xF); // E51E push 0xf
            m.push(m.si); // E520 push si
            m.far(.att_4cec, 0xE521); // E521 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E526 or ax, ax
            if (m.sf != m.of) continue :sw 0xE52D; // E528 jl 0xe52d
            continue :sw 0xE5E8; // E52A jmp 0xe5e8
        },
        0xE52D => {
            m.mark(0xE52D);
            m.si = m.di +% 0x0001; // E52D lea si, [di + 1]
            continue :sw 0xE542; // E530 jmp 0xe542
        },
        0xE532 => {
            m.mark(0xE532);
            m.push(0xF); // E532 push 0xf
            m.push(m.si); // E534 push si
            m.far(.att_4cec, 0xE535); // E535 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E53A or ax, ax
            if (m.sf != m.of) continue :sw 0xE541; // E53C jl 0xe541
            continue :sw 0xE5E8; // E53E jmp 0xe5e8
        },
        0xE541 => {
            m.mark(0xE541);
            m.si = m.inc(u16, m.si); // E541 inc si
            continue :sw 0xE542; // falls through
        },
        0xE542 => {
            m.mark(0xE542);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E542 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE532; // E547 je 0xe532
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // E549 cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xE55F; // E54E jge 0xe55f
            m.push(0xF); // E550 push 0xf
            m.push(m.si); // E552 push si
            m.far(.att_4cec, 0xE553); // E553 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E558 or ax, ax
            if (m.sf != m.of) continue :sw 0xE55F; // E55A jl 0xe55f
            continue :sw 0xE5E8; // E55C jmp 0xe5e8
        },
        0xE55F => {
            m.mark(0xE55F);
            m.si = m.di +% 0xFFFF; // E55F lea si, [di - 1]
            continue :sw 0xE573; // E562 jmp 0xe573
        },
        0xE566 => {
            m.mark(0xE566);
            m.push(0xF); // E566 push 0xf
            m.push(m.si); // E568 push si
            m.far(.att_4cec, 0xE569); // E569 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E56E or ax, ax
            if (m.sf == m.of) continue :sw 0xE5E8; // E570 jge 0xe5e8
            m.si = m.dec(u16, m.si); // E572 dec si
            continue :sw 0xE573; // falls through
        },
        0xE573 => {
            m.mark(0xE573);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E573 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE566; // E578 je 0xe566
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // E57A cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xE58D; // E57F jge 0xe58d
            m.push(0xF); // E581 push 0xf
            m.push(m.si); // E583 push si
            m.far(.att_4cec, 0xE584); // E584 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E589 or ax, ax
            if (m.sf == m.of) continue :sw 0xE5E8; // E58B jge 0xe5e8
            continue :sw 0xE58D; // falls through
        },
        0xE58D => {
            m.mark(0xE58D);
            m.si = m.di +% 0xFFF6; // E58D lea si, [di - 0xa]
            continue :sw 0xE5A1; // E590 jmp 0xe5a1
        },
        0xE592 => {
            m.mark(0xE592);
            m.push(0xF); // E592 push 0xf
            m.push(m.si); // E594 push si
            m.far(.att_4cec, 0xE595); // E595 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E59A or ax, ax
            if (m.sf == m.of) continue :sw 0xE5E8; // E59C jge 0xe5e8
            m.si = m.sub(u16, m.si, 0xA); // E59E sub si, 0xa
            continue :sw 0xE5A1; // falls through
        },
        0xE5A1 => {
            m.mark(0xE5A1);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E5A1 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE592; // E5A6 je 0xe592
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // E5A8 cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xE5BB; // E5AD jge 0xe5bb
            m.push(0xF); // E5AF push 0xf
            m.push(m.si); // E5B1 push si
            m.far(.att_4cec, 0xE5B2); // E5B2 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E5B7 or ax, ax
            if (m.sf == m.of) continue :sw 0xE5E8; // E5B9 jge 0xe5e8
            continue :sw 0xE5BB; // falls through
        },
        0xE5BB => {
            m.mark(0xE5BB);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x12C)); // E5BB add word ptr [bp - 4], 0x12c
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // E5C0 cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xE5D6; // E5C5 je 0xe5d6
            m.ax = m.rw(0xA5EC); // E5C7 mov ax, word ptr [0xa5ec]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // E5CA cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xE5E8; // E5CD jge 0xe5e8
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x384)); // E5CF add word ptr [bp - 2], 0x384
            continue :sw 0xE5E3; // E5D4 jmp 0xe5e3
        },
        0xE5D6 => {
            m.mark(0xE5D6);
            m.ax = m.rw(0x9356); // E5D6 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // E5D9 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xE5E8; // E5DC jge 0xe5e8
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x2BC)); // E5DE add word ptr [bp - 2], 0x2bc
            continue :sw 0xE5E3; // falls through
        },
        0xE5E3 => {
            m.mark(0xE5E3);
            m.bx = m.rw(m.bp +% 0x000A); // E5E3 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // E5E6 inc byte ptr [bx]
            continue :sw 0xE5E8; // falls through
        },
        0xE5E8 => {
            m.mark(0xE5E8);
            m.wb(m.di +% 0x9EF6, 0xB); // E5E8 mov byte ptr [di - 0x610a], 0xb
            continue :sw 0xE5ED; // falls through
        },
        0xE5ED => {
            m.mark(0xE5ED);
            m.setAl(m.rb(0xA04E)); // E5ED mov al, byte ptr [0xa04e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // E5F0 sub ah, ah
            m.di = m.ax; // E5F2 mov di, ax
            m.cmp(u16, m.di, 0x62); // E5F4 cmp di, 0x62
            if (m.zf or m.sf != m.of) continue :sw 0xE5FC; // E5F7 jle 0xe5fc
            continue :sw 0xEA4F; // E5F9 jmp 0xea4f
        },
        0xE5FC => {
            m.mark(0xE5FC);
            m.cmp(u8, m.rb(m.di +% 0xA164), 0x9); // E5FC cmp byte ptr [di - 0x5e9c], 9
            if (m.sf == m.of) continue :sw 0xE606; // E601 jge 0xe606
            continue :sw 0xE766; // E603 jmp 0xe766
        },
        0xE606 => {
            m.mark(0xE606);
            m.cmp(u8, m.rb(m.di +% 0xA164), 0xC); // E606 cmp byte ptr [di - 0x5e9c], 0xc
            if (m.zf or m.sf != m.of) continue :sw 0xE610; // E60B jle 0xe610
            continue :sw 0xE766; // E60D jmp 0xe766
        },
        0xE610 => {
            m.mark(0xE610);
            m.setAl(m.rb(m.di +% 0xA164)); // E610 mov al, byte ptr [di - 0x5e9c]
            m.cbw(); // E614 cbw
            m.bx = m.ax; // E615 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // E617 mov al, byte ptr [bx + 0x490]
            m.cbw(); // E61B cbw
            m.si = m.ax; // E61C mov si, ax
            continue :sw 0xE61E; // falls through
        },
        0xE61E => {
            m.mark(0xE61E);
            m.di = m.add(u16, m.di, m.si); // E61E add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // E620 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xE61E; // E625 je 0xe61e
            m.si = m.di; // E627 mov si, di
            m.setAl(m.rb(0xA04E)); // E629 mov al, byte ptr [0xa04e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // E62C sub ah, ah
            m.di = m.ax; // E62E mov di, ax
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x3); // E630 cmp byte ptr [si - 0x610a], 3
            if (!m.zf) continue :sw 0xE662; // E635 jne 0xe662
            m.ax = m.rw(0x9356); // E637 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // E63A cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xE64C; // E63D jge 0xe64c
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x514)); // E63F add word ptr [bp - 2], 0x514
            m.bx = m.rw(m.bp +% 0x000A); // E644 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // E647 inc byte ptr [bx]
            continue :sw 0xE656; // E649 jmp 0xe656
        },
        0xE64C => {
            m.mark(0xE64C);
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // E64C cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xE656; // E651 je 0xe656
            continue :sw 0xE1DB; // E653 jmp 0xe1db
        },
        0xE656 => {
            m.mark(0xE656);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x12C)); // E656 add word ptr [bp - 4], 0x12c
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // E65B inc word ptr [bp - 6]
            continue :sw 0xEA4F; // E65E jmp 0xea4f
        },
        0xE662 => {
            m.mark(0xE662);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x5); // E662 cmp byte ptr [si - 0x610a], 5
            if (m.zf) continue :sw 0xE66C; // E667 je 0xe66c
            continue :sw 0xE766; // E669 jmp 0xe766
        },
        0xE66C => {
            m.mark(0xE66C);
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // E66C cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xE676; // E671 je 0xe676
            continue :sw 0xE1F7; // E673 jmp 0xe1f7
        },
        0xE676 => {
            m.mark(0xE676);
            m.si = m.di +% 0x00B0; // E676 lea si, [di + 0xb0]
            m.bx = m.si; // E67A mov bx, si
            m.setAl(m.rb(0xA03B)); // E67C mov al, byte ptr [0xa03b]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // E67F sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // E681 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x09B8)); // E683 mov al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // E687 mov bx, si
            m.setCl(m.rb(0xA03A)); // E689 mov cl, byte ptr [0xa03a]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // E68D sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // E68F sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // E691 or al, byte ptr [bx + 0x9b8]
            if (m.zf) continue :sw 0xE6B4; // E695 je 0xe6b4
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x15E)); // E697 add word ptr [bp - 4], 0x15e
            m.ax = m.rw(0x9356); // E69C mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // E69F cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xE6A7; // E6A2 jl 0xe6a7
            continue :sw 0xEA4F; // E6A4 jmp 0xea4f
        },
        0xE6A7 => {
            m.mark(0xE6A7);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x320)); // E6A7 add word ptr [bp - 2], 0x320
            continue :sw 0xE6AC; // falls through
        },
        0xE6AC => {
            m.mark(0xE6AC);
            m.bx = m.rw(m.bp +% 0x000A); // E6AC mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // E6AF inc byte ptr [bx]
            continue :sw 0xEA4F; // E6B1 jmp 0xea4f
        },
        0xE6B4 => {
            m.mark(0xE6B4);
            m.cmp(u8, m.rb(m.di +% 0xA164), 0x9); // E6B4 cmp byte ptr [di - 0x5e9c], 9
            if (m.zf) continue :sw 0xE6C2; // E6B9 je 0xe6c2
            m.cmp(u8, m.rb(m.di +% 0xA164), 0xB); // E6BB cmp byte ptr [di - 0x5e9c], 0xb
            if (!m.zf) continue :sw 0xE716; // E6C0 jne 0xe716
            continue :sw 0xE6C2; // falls through
        },
        0xE6C2 => {
            m.mark(0xE6C2);
            m.si = m.di +% 0x000B; // E6C2 lea si, [di + 0xb]
            continue :sw 0xE6CB; // E6C5 jmp 0xe6cb
        },
        0xE6C8 => {
            m.mark(0xE6C8);
            m.si = m.add(u16, m.si, 0xB); // E6C8 add si, 0xb
            continue :sw 0xE6CB; // falls through
        },
        0xE6CB => {
            m.mark(0xE6CB);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E6CB cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE6C8; // E6D0 je 0xe6c8
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x3); // E6D2 cmp byte ptr [si - 0x610a], 3
            if (!m.zf) continue :sw 0xE6F8; // E6D7 jne 0xe6f8
            m.ax = m.si; // E6D9 mov ax, si
            m.ax = m.sub(u16, m.ax, m.di); // E6DB sub ax, di
            continue :sw 0xE6DD; // falls through
        },
        0xE6DD => {
            m.mark(0xE6DD);
            m.cmp(u16, m.ax, 0xB); // E6DD cmp ax, 0xb
            continue :sw 0xE6E0; // falls through
        },
        0xE6E0 => {
            m.mark(0xE6E0);
            if (!m.zf) continue :sw 0xE6E7; // E6E0 jne 0xe6e7
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x12C)); // E6E2 add word ptr [bp - 4], 0x12c
            continue :sw 0xE6E7; // falls through
        },
        0xE6E7 => {
            m.mark(0xE6E7);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0xC8)); // E6E7 add word ptr [bp - 4], 0xc8
            m.ax = m.rw(0x9356); // E6EC mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // E6EF cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xE771; // E6F2 jge 0xe771
            continue :sw 0xE8EC; // E6F4 jmp 0xe8ec
        },
        0xE6F8 => {
            m.mark(0xE6F8);
            m.si = m.di +% 0xFFF5; // E6F8 lea si, [di - 0xb]
            continue :sw 0xE701; // E6FB jmp 0xe701
        },
        0xE6FE => {
            m.mark(0xE6FE);
            m.si = m.sub(u16, m.si, 0xB); // E6FE sub si, 0xb
            continue :sw 0xE701; // falls through
        },
        0xE701 => {
            m.mark(0xE701);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E701 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE6FE; // E706 je 0xe6fe
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x3); // E708 cmp byte ptr [si - 0x610a], 3
            if (!m.zf) continue :sw 0xE754; // E70D jne 0xe754
            m.ax = m.di; // E70F mov ax, di
            m.ax = m.sub(u16, m.ax, m.si); // E711 sub ax, si
            continue :sw 0xE6DD; // E713 jmp 0xe6dd
        },
        0xE716 => {
            m.mark(0xE716);
            m.si = m.di +% 0x0009; // E716 lea si, [di + 9]
            continue :sw 0xE71F; // E719 jmp 0xe71f
        },
        0xE71C => {
            m.mark(0xE71C);
            m.si = m.add(u16, m.si, 0x9); // E71C add si, 9
            continue :sw 0xE71F; // falls through
        },
        0xE71F => {
            m.mark(0xE71F);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E71F cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE71C; // E724 je 0xe71c
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x3); // E726 cmp byte ptr [si - 0x610a], 3
            if (!m.zf) continue :sw 0xE734; // E72B jne 0xe734
            m.ax = m.si; // E72D mov ax, si
            m.ax = m.sub(u16, m.ax, m.di); // E72F sub ax, di
            continue :sw 0xE74F; // E731 jmp 0xe74f
        },
        0xE734 => {
            m.mark(0xE734);
            m.si = m.di +% 0xFFF7; // E734 lea si, [di - 9]
            continue :sw 0xE73D; // E737 jmp 0xe73d
        },
        0xE73A => {
            m.mark(0xE73A);
            m.si = m.sub(u16, m.si, 0x9); // E73A sub si, 9
            continue :sw 0xE73D; // falls through
        },
        0xE73D => {
            m.mark(0xE73D);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E73D cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE73A; // E742 je 0xe73a
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x3); // E744 cmp byte ptr [si - 0x610a], 3
            if (!m.zf) continue :sw 0xE754; // E749 jne 0xe754
            m.ax = m.di; // E74B mov ax, di
            m.ax = m.sub(u16, m.ax, m.si); // E74D sub ax, si
            continue :sw 0xE74F; // falls through
        },
        0xE74F => {
            m.mark(0xE74F);
            m.cmp(u16, m.ax, 0x9); // E74F cmp ax, 9
            continue :sw 0xE6E0; // E752 jmp 0xe6e0
        },
        0xE754 => {
            m.mark(0xE754);
            m.push(0x1E); // E754 push 0x1e
            m.push(m.di); // E756 push di
            m.far(.att_4cec, 0xE757); // E757 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E75C or ax, ax
            if (m.sf != m.of) continue :sw 0xE763; // E75E jl 0xe763
            continue :sw 0xEA4F; // E760 jmp 0xea4f
        },
        0xE763 => {
            m.mark(0xE763);
            continue :sw 0xE6E7; // E763 jmp 0xe6e7
        },
        0xE766 => {
            m.mark(0xE766);
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // E766 cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xE7AC; // E76B je 0xe7ac
            m.ww(m.bp +% 0xFFFA, m.add(u16, m.rw(m.bp +% 0xFFFA), 0xD)); // E76D add word ptr [bp - 6], 0xd
            continue :sw 0xE771; // falls through
        },
        0xE771 => {
            m.mark(0xE771);
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // E771 inc word ptr [bp - 6]
            continue :sw 0xE774; // falls through
        },
        0xE774 => {
            m.mark(0xE774);
            m.cmp(u16, m.di, 0x5B); // E774 cmp di, 0x5b
            if (m.sf == m.of) continue :sw 0xE77C; // E777 jge 0xe77c
            continue :sw 0xE955; // E779 jmp 0xe955
        },
        0xE77C => {
            m.mark(0xE77C);
            m.cmp(u8, m.rb(m.di +% 0x9EEC), 0x0); // E77C cmp byte ptr [di - 0x6114], 0
            if (!m.zf) continue :sw 0xE786; // E781 jne 0xe786
            continue :sw 0xE955; // E783 jmp 0xe955
        },
        0xE786 => {
            m.mark(0xE786);
            m.cmp(u8, m.rb(m.di +% 0x9EEC), 0x1); // E786 cmp byte ptr [di - 0x6114], 1
            if (m.zf) continue :sw 0xE790; // E78B je 0xe790
            continue :sw 0xE93C; // E78D jmp 0xe93c
        },
        0xE790 => {
            m.mark(0xE790);
            m.ax = m.rw(0x9356); // E790 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // E793 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xE79B; // E796 jge 0xe79b
            continue :sw 0xE8EC; // E798 jmp 0xe8ec
        },
        0xE79B => {
            m.mark(0xE79B);
            m.cmp(u16, m.rw(m.bp +% 0xFFFA), 0x0); // E79B cmp word ptr [bp - 6], 0
            if (!m.zf) continue :sw 0xE7A4; // E79F jne 0xe7a4
            continue :sw 0xE955; // E7A1 jmp 0xe955
        },
        0xE7A4 => {
            m.mark(0xE7A4);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0xC8)); // E7A4 add word ptr [bp - 4], 0xc8
            continue :sw 0xE955; // E7A9 jmp 0xe955
        },
        0xE7AC => {
            m.mark(0xE7AC);
            m.si = m.di +% 0x00B0; // E7AC lea si, [di + 0xb0]
            m.bx = m.si; // E7B0 mov bx, si
            m.setAl(m.rb(0xA03B)); // E7B2 mov al, byte ptr [0xa03b]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // E7B5 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // E7B7 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x09B8)); // E7B9 mov al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // E7BD mov bx, si
            m.setCl(m.rb(0xA03A)); // E7BF mov cl, byte ptr [0xa03a]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // E7C3 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // E7C5 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // E7C7 or al, byte ptr [bx + 0x9b8]
            if (!m.zf) continue :sw 0xE771; // E7CB jne 0xe771
            m.cmp(u8, m.rb(m.di +% 0x0E16), m.ah()); // E7CD cmp byte ptr [di + 0xe16], ah
            if (!m.zf) continue :sw 0xE7EC; // E7D1 jne 0xe7ec
            m.bx = m.si; // E7D3 mov bx, si
            m.setAl(m.rb(0xA03C)); // E7D5 mov al, byte ptr [0xa03c]
            m.bx = m.sub(u16, m.bx, m.ax); // E7D8 sub bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), m.ah()); // E7DA cmp byte ptr [bx + 0xab6], ah
            if (!m.zf) continue :sw 0xE7E3; // E7DE jne 0xe7e3
            continue :sw 0xE886; // E7E0 jmp 0xe886
        },
        0xE7E3 => {
            m.mark(0xE7E3);
            m.cmp(u8, m.al(), 0x63); // E7E3 cmp al, 0x63
            if (m.cf) continue :sw 0xE7EA; // E7E5 jb 0xe7ea
            continue :sw 0xE886; // E7E7 jmp 0xe886
        },
        0xE7EA => {
            m.mark(0xE7EA);
            continue :sw 0xE802; // E7EA jmp 0xe802
        },
        0xE7EC => {
            m.mark(0xE7EC);
            m.bx = m.si; // E7EC mov bx, si
            m.setAl(m.rb(0xA03D)); // E7EE mov al, byte ptr [0xa03d]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // E7F1 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // E7F3 sub bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), m.ah()); // E7F5 cmp byte ptr [bx + 0xab6], ah
            if (!m.zf) continue :sw 0xE7FE; // E7F9 jne 0xe7fe
            continue :sw 0xE886; // E7FB jmp 0xe886
        },
        0xE7FE => {
            m.mark(0xE7FE);
            m.bx = m.si; // E7FE mov bx, si
            m.bx = m.sub(u16, m.bx, m.ax); // E800 sub bx, ax
            continue :sw 0xE802; // falls through
        },
        0xE802 => {
            m.mark(0xE802);
            m.setAl(m.rb(m.bx +% 0x0AB6)); // E802 mov al, byte ptr [bx + 0xab6]
            m.cbw(); // E806 cbw
            m.ww(m.bp +% 0xFFF6, m.ax); // E807 mov word ptr [bp - 0xa], ax
            m.si = m.ax; // E80A mov si, ax
            m.si = m.add(u16, m.si, m.di); // E80C add si, di
            continue :sw 0xE815; // E80E jmp 0xe815
        },
        0xE812 => {
            m.mark(0xE812);
            m.si = m.add(u16, m.si, m.rw(m.bp +% 0xFFF6)); // E812 add si, word ptr [bp - 0xa]
            continue :sw 0xE815; // falls through
        },
        0xE815 => {
            m.mark(0xE815);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E815 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE812; // E81A je 0xe812
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x3); // E81C cmp byte ptr [si - 0x610a], 3
            if (!m.zf) continue :sw 0xE882; // E821 jne 0xe882
            m.ax = m.si; // E823 mov ax, si
            m.ax = m.sub(u16, m.ax, m.rw(m.bp +% 0xFFF6)); // E825 sub ax, word ptr [bp - 0xa]
            m.cmp(u16, m.ax, m.di); // E828 cmp ax, di
            if (!m.zf) continue :sw 0xE84E; // E82A jne 0xe84e
            m.si = m.di; // E82C mov si, di
            continue :sw 0xE82E; // falls through
        },
        0xE82E => {
            m.mark(0xE82E);
            m.si = m.sub(u16, m.si, m.rw(m.bp +% 0xFFF6)); // E82E sub si, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E831 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE82E; // E836 je 0xe82e
            m.setAl(m.rb(m.si +% 0x9EF6)); // E838 mov al, byte ptr [si - 0x610a]
            m.cbw(); // E83C cbw
            m.bx = m.ax; // E83D mov bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x127E), 0x0); // E83F cmp byte ptr [bx + 0x127e], 0
            if (m.zf) continue :sw 0xE86B; // E844 je 0xe86b
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0xC8)); // E846 add word ptr [bp - 4], 0xc8
            continue :sw 0xE6E7; // E84B jmp 0xe6e7
        },
        0xE84E => {
            m.mark(0xE84E);
            m.si = m.di; // E84E mov si, di
            continue :sw 0xE850; // falls through
        },
        0xE850 => {
            m.mark(0xE850);
            m.si = m.sub(u16, m.si, m.rw(m.bp +% 0xFFF6)); // E850 sub si, word ptr [bp - 0xa]
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E853 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE850; // E858 je 0xe850
            m.setAl(m.rb(m.si +% 0x9EF6)); // E85A mov al, byte ptr [si - 0x610a]
            m.cbw(); // E85E cbw
            m.bx = m.ax; // E85F mov bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x127E), 0x0); // E861 cmp byte ptr [bx + 0x127e], 0
            if (m.zf) continue :sw 0xE86B; // E866 je 0xe86b
            continue :sw 0xE6E7; // E868 jmp 0xe6e7
        },
        0xE86B => {
            m.mark(0xE86B);
            m.ax = m.rw(0xA272); // E86B mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // E86E cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xE876; // E871 jle 0xe876
            continue :sw 0xE771; // E873 jmp 0xe771
        },
        0xE876 => {
            m.mark(0xE876);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x64)); // E876 add word ptr [bp - 2], 0x64
            m.bx = m.rw(m.bp +% 0x000A); // E87A mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // E87D inc byte ptr [bx]
            continue :sw 0xE771; // E87F jmp 0xe771
        },
        0xE882 => {
            m.mark(0xE882);
            m.si = m.di +% 0x00B0; // E882 lea si, [di + 0xb0]
            continue :sw 0xE886; // falls through
        },
        0xE886 => {
            m.mark(0xE886);
            m.bx = m.si; // E886 mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // E888 sub bx, word ptr [bp - 0xc]
            m.cmp(u8, m.rb(m.bx +% 0x0AB6), 0x0); // E88B cmp byte ptr [bx + 0xab6], 0
            if (m.zf) continue :sw 0xE8CA; // E890 je 0xe8ca
            m.setAl(m.rb(m.bx +% 0x0AB6)); // E892 mov al, byte ptr [bx + 0xab6]
            m.cbw(); // E896 cbw
            m.ww(m.bp +% 0xFFF6, m.ax); // E897 mov word ptr [bp - 0xa], ax
            m.ax = m.add(u16, m.ax, m.di); // E89A add ax, di
            m.si = m.ax; // E89C mov si, ax
            continue :sw 0xE8A3; // E89E jmp 0xe8a3
        },
        0xE8A0 => {
            m.mark(0xE8A0);
            m.si = m.add(u16, m.si, m.rw(m.bp +% 0xFFF6)); // E8A0 add si, word ptr [bp - 0xa]
            continue :sw 0xE8A3; // falls through
        },
        0xE8A3 => {
            m.mark(0xE8A3);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E8A3 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE8A0; // E8A8 je 0xe8a0
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x5); // E8AA cmp byte ptr [si - 0x610a], 5
            if (!m.zf) continue :sw 0xE8C6; // E8AF jne 0xe8c6
            m.push(0x1E); // E8B1 push 0x1e
            m.push(m.di); // E8B3 push di
            m.far(.att_4cec, 0xE8B4); // E8B4 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E8B9 or ax, ax
            if (m.sf != m.of) continue :sw 0xE8C0; // E8BB jl 0xe8c0
            continue :sw 0xEA4F; // E8BD jmp 0xea4f
        },
        0xE8C0 => {
            m.mark(0xE8C0);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // E8C0 inc word ptr [bp - 8]
            continue :sw 0xE774; // E8C3 jmp 0xe774
        },
        0xE8C6 => {
            m.mark(0xE8C6);
            m.si = m.di +% 0x00B0; // E8C6 lea si, [di + 0xb0]
            continue :sw 0xE8CA; // falls through
        },
        0xE8CA => {
            m.mark(0xE8CA);
            m.bx = m.di; // E8CA mov bx, di
            m.setAl(m.rb(0xA041)); // E8CC mov al, byte ptr [0xa041]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // E8CF sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // E8D1 sub bx, ax
            m.cmp(u8, m.rb(m.bx +% 0x0CFF), m.ah()); // E8D3 cmp byte ptr [bx + 0xcff], ah
            if (m.zf) continue :sw 0xE8F4; // E8D7 je 0xe8f4
            m.push(0x1E); // E8D9 push 0x1e
            m.push(m.di); // E8DB push di
            m.far(.att_4cec, 0xE8DC); // E8DC lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E8E1 or ax, ax
            if (m.sf == m.of) continue :sw 0xE8F4; // E8E3 jge 0xe8f4
            m.cmp(u8, m.rb(0xA5F5), 0x0); // E8E5 cmp byte ptr [0xa5f5], 0
            if (m.zf) continue :sw 0xE8C0; // E8EA je 0xe8c0
            continue :sw 0xE8EC; // falls through
        },
        0xE8EC => {
            m.mark(0xE8EC);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x2BC)); // E8EC add word ptr [bp - 2], 0x2bc
            continue :sw 0xE6AC; // E8F1 jmp 0xe6ac
        },
        0xE8F4 => {
            m.mark(0xE8F4);
            m.bx = m.si; // E8F4 mov bx, si
            m.setAl(m.rb(0xA03E)); // E8F6 mov al, byte ptr [0xa03e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // E8F9 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // E8FB sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0BB4)); // E8FD mov al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // E901 mov bx, si
            m.setCl(m.rb(0xA03F)); // E903 mov cl, byte ptr [0xa03f]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // E907 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // E909 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // E90B or al, byte ptr [bx + 0xbb4]
            m.@"test"(u8, m.al(), 0x1); // E90F test al, 1
            if (!m.zf) continue :sw 0xE916; // E911 jne 0xe916
            continue :sw 0xEA4F; // E913 jmp 0xea4f
        },
        0xE916 => {
            m.mark(0xE916);
            m.push(0x1E); // E916 push 0x1e
            m.push(m.di); // E918 push di
            m.far(.att_4cec, 0xE919); // E919 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E91E or ax, ax
            if (m.sf != m.of) continue :sw 0xE925; // E920 jl 0xe925
            continue :sw 0xEA4F; // E922 jmp 0xea4f
        },
        0xE925 => {
            m.mark(0xE925);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // E925 inc word ptr [bp - 8]
            m.ax = m.rw(0xA272); // E928 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // E92B cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xE933; // E92E jle 0xe933
            continue :sw 0xEA4F; // E930 jmp 0xea4f
        },
        0xE933 => {
            m.mark(0xE933);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xFA)); // E933 add word ptr [bp - 2], 0xfa
            continue :sw 0xE6AC; // E938 jmp 0xe6ac
        },
        0xE93C => {
            m.mark(0xE93C);
            m.cmp(u8, m.rb(m.di +% 0x9EEC), 0x7); // E93C cmp byte ptr [di - 0x6114], 7
            if (m.zf or m.sf != m.of) continue :sw 0xE955; // E941 jle 0xe955
            m.ax = m.rw(0xA272); // E943 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // E946 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xE955; // E949 jg 0xe955
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x12C)); // E94B add word ptr [bp - 2], 0x12c
            m.bx = m.rw(m.bp +% 0x000A); // E950 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // E953 inc byte ptr [bx]
            continue :sw 0xE955; // falls through
        },
        0xE955 => {
            m.mark(0xE955);
            m.wb(m.di +% 0x9EF6, 0x0); // E955 mov byte ptr [di - 0x610a], 0
            m.si = m.di +% 0x000A; // E95A lea si, [di + 0xa]
            continue :sw 0xE972; // E95D jmp 0xe972
        },
        0xE960 => {
            m.mark(0xE960);
            m.push(0xF); // E960 push 0xf
            m.push(m.si); // E962 push si
            m.far(.att_4cec, 0xE963); // E963 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E968 or ax, ax
            if (m.sf != m.of) continue :sw 0xE96F; // E96A jl 0xe96f
            continue :sw 0xEA4A; // E96C jmp 0xea4a
        },
        0xE96F => {
            m.mark(0xE96F);
            m.si = m.add(u16, m.si, 0xA); // E96F add si, 0xa
            continue :sw 0xE972; // falls through
        },
        0xE972 => {
            m.mark(0xE972);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E972 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE960; // E977 je 0xe960
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // E979 cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xE98F; // E97E jge 0xe98f
            m.push(0xF); // E980 push 0xf
            m.push(m.si); // E982 push si
            m.far(.att_4cec, 0xE983); // E983 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E988 or ax, ax
            if (m.sf != m.of) continue :sw 0xE98F; // E98A jl 0xe98f
            continue :sw 0xEA4A; // E98C jmp 0xea4a
        },
        0xE98F => {
            m.mark(0xE98F);
            m.si = m.di +% 0x0001; // E98F lea si, [di + 1]
            continue :sw 0xE9A4; // E992 jmp 0xe9a4
        },
        0xE994 => {
            m.mark(0xE994);
            m.push(0xF); // E994 push 0xf
            m.push(m.si); // E996 push si
            m.far(.att_4cec, 0xE997); // E997 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E99C or ax, ax
            if (m.sf != m.of) continue :sw 0xE9A3; // E99E jl 0xe9a3
            continue :sw 0xEA4A; // E9A0 jmp 0xea4a
        },
        0xE9A3 => {
            m.mark(0xE9A3);
            m.si = m.inc(u16, m.si); // E9A3 inc si
            continue :sw 0xE9A4; // falls through
        },
        0xE9A4 => {
            m.mark(0xE9A4);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E9A4 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE994; // E9A9 je 0xe994
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // E9AB cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xE9C1; // E9B0 jge 0xe9c1
            m.push(0xF); // E9B2 push 0xf
            m.push(m.si); // E9B4 push si
            m.far(.att_4cec, 0xE9B5); // E9B5 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E9BA or ax, ax
            if (m.sf != m.of) continue :sw 0xE9C1; // E9BC jl 0xe9c1
            continue :sw 0xEA4A; // E9BE jmp 0xea4a
        },
        0xE9C1 => {
            m.mark(0xE9C1);
            m.si = m.di +% 0xFFFF; // E9C1 lea si, [di - 1]
            continue :sw 0xE9D5; // E9C4 jmp 0xe9d5
        },
        0xE9C8 => {
            m.mark(0xE9C8);
            m.push(0xF); // E9C8 push 0xf
            m.push(m.si); // E9CA push si
            m.far(.att_4cec, 0xE9CB); // E9CB lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E9D0 or ax, ax
            if (m.sf == m.of) continue :sw 0xEA4A; // E9D2 jge 0xea4a
            m.si = m.dec(u16, m.si); // E9D4 dec si
            continue :sw 0xE9D5; // falls through
        },
        0xE9D5 => {
            m.mark(0xE9D5);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // E9D5 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE9C8; // E9DA je 0xe9c8
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // E9DC cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xE9EF; // E9E1 jge 0xe9ef
            m.push(0xF); // E9E3 push 0xf
            m.push(m.si); // E9E5 push si
            m.far(.att_4cec, 0xE9E6); // E9E6 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E9EB or ax, ax
            if (m.sf == m.of) continue :sw 0xEA4A; // E9ED jge 0xea4a
            continue :sw 0xE9EF; // falls through
        },
        0xE9EF => {
            m.mark(0xE9EF);
            m.si = m.di +% 0xFFF6; // E9EF lea si, [di - 0xa]
            continue :sw 0xEA03; // E9F2 jmp 0xea03
        },
        0xE9F4 => {
            m.mark(0xE9F4);
            m.push(0xF); // E9F4 push 0xf
            m.push(m.si); // E9F6 push si
            m.far(.att_4cec, 0xE9F7); // E9F7 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // E9FC or ax, ax
            if (m.sf == m.of) continue :sw 0xEA4A; // E9FE jge 0xea4a
            m.si = m.sub(u16, m.si, 0xA); // EA00 sub si, 0xa
            continue :sw 0xEA03; // falls through
        },
        0xEA03 => {
            m.mark(0xEA03);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // EA03 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xE9F4; // EA08 je 0xe9f4
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // EA0A cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xEA1D; // EA0F jge 0xea1d
            m.push(0xF); // EA11 push 0xf
            m.push(m.si); // EA13 push si
            m.far(.att_4cec, 0xEA14); // EA14 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EA19 or ax, ax
            if (m.sf == m.of) continue :sw 0xEA4A; // EA1B jge 0xea4a
            continue :sw 0xEA1D; // falls through
        },
        0xEA1D => {
            m.mark(0xEA1D);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x12C)); // EA1D add word ptr [bp - 4], 0x12c
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // EA22 cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xEA38; // EA27 je 0xea38
            m.ax = m.rw(0xA5EC); // EA29 mov ax, word ptr [0xa5ec]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // EA2C cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xEA4A; // EA2F jge 0xea4a
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x384)); // EA31 add word ptr [bp - 2], 0x384
            continue :sw 0xEA45; // EA36 jmp 0xea45
        },
        0xEA38 => {
            m.mark(0xEA38);
            m.ax = m.rw(0x9356); // EA38 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // EA3B cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xEA4A; // EA3E jge 0xea4a
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x2BC)); // EA40 add word ptr [bp - 2], 0x2bc
            continue :sw 0xEA45; // falls through
        },
        0xEA45 => {
            m.mark(0xEA45);
            m.bx = m.rw(m.bp +% 0x000A); // EA45 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // EA48 inc byte ptr [bx]
            continue :sw 0xEA4A; // falls through
        },
        0xEA4A => {
            m.mark(0xEA4A);
            m.wb(m.di +% 0x9EF6, 0xB); // EA4A mov byte ptr [di - 0x610a], 0xb
            continue :sw 0xEA4F; // falls through
        },
        0xEA4F => {
            m.mark(0xEA4F);
            m.setAl(m.rb(0xA04A)); // EA4F mov al, byte ptr [0xa04a]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // EA52 sub ah, ah
            m.di = m.ax; // EA54 mov di, ax
            m.cmp(u16, m.di, 0x62); // EA56 cmp di, 0x62
            if (m.zf or m.sf != m.of) continue :sw 0xEA5E; // EA59 jle 0xea5e
            continue :sw 0xEBDD; // EA5B jmp 0xebdd
        },
        0xEA5E => {
            m.mark(0xEA5E);
            m.cmp(u8, m.rb(m.di +% 0xA164), m.ah()); // EA5E cmp byte ptr [di - 0x5e9c], ah
            if (!m.zf) continue :sw 0xEA67; // EA62 jne 0xea67
            continue :sw 0xEAF2; // EA64 jmp 0xeaf2
        },
        0xEA67 => {
            m.mark(0xEA67);
            m.setAl(m.rb(m.di +% 0xA164)); // EA67 mov al, byte ptr [di - 0x5e9c]
            m.cbw(); // EA6B cbw
            m.bx = m.ax; // EA6C mov bx, ax
            m.setAl(m.rb(m.bx +% 0x047E)); // EA6E mov al, byte ptr [bx + 0x47e]
            m.wb(m.bp +% 0xFFF2, m.al()); // EA72 mov byte ptr [bp - 0xe], al
            m.setAl(m.rb(m.bx +% 0x0490)); // EA75 mov al, byte ptr [bx + 0x490]
            m.cbw(); // EA79 cbw
            m.si = m.ax; // EA7A mov si, ax
            continue :sw 0xEA7C; // falls through
        },
        0xEA7C => {
            m.mark(0xEA7C);
            m.di = m.add(u16, m.di, m.si); // EA7C add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // EA7E cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xEA7C; // EA83 je 0xea7c
            m.si = m.di; // EA85 mov si, di
            m.setAl(m.rb(0xA04A)); // EA87 mov al, byte ptr [0xa04a]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // EA8A sub ah, ah
            m.di = m.ax; // EA8C mov di, ax
            m.cx = m.di; // EA8E mov cx, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // EA90 mov al, byte ptr [si - 0x610a]
            m.cbw(); // EA94 cbw
            m.bx = m.ax; // EA95 mov bx, ax
            m.setAl(m.rb(m.bp +% 0xFFF2)); // EA97 mov al, byte ptr [bp - 0xe]
            m.@"test"(u8, m.rb(m.bx +% 0x0470), m.al()); // EA9A test byte ptr [bx + 0x470], al
            if (m.zf) continue :sw 0xEAF2; // EA9E je 0xeaf2
            m.bx = m.cx; // EAA0 mov bx, cx
            m.cmp(u8, m.rb(m.bx +% 0xA51C), m.ch()); // EAA2 cmp byte ptr [bx - 0x5ae4], ch
            if (m.zf) continue :sw 0xEAAB; // EAA6 je 0xeaab
            continue :sw 0xF55C; // EAA8 jmp 0xf55c
        },
        0xEAAB => {
            m.mark(0xEAAB);
            m.push(0x12); // EAAB push 0x12
            m.push(m.di); // EAAD push di
            m.far(.att_4cec, 0xEAAE); // EAAE lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EAB3 or ax, ax
            if (m.sf != m.of) continue :sw 0xEABA; // EAB5 jl 0xeaba
            continue :sw 0xEBDD; // EAB7 jmp 0xebdd
        },
        0xEABA => {
            m.mark(0xEABA);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // EABA inc word ptr [bp - 8]
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // EABD cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xEAC7; // EAC2 je 0xeac7
            continue :sw 0xEBDD; // EAC4 jmp 0xebdd
        },
        0xEAC7 => {
            m.mark(0xEAC7);
            m.cmp(u8, m.rb(0x931B), 0x1); // EAC7 cmp byte ptr [0x931b], 1
            if (m.zf or m.sf != m.of) continue :sw 0xEAD4; // EACC jle 0xead4
            m.ax = 0x80; // EACE mov ax, 0x80
            continue :sw 0xEAD7; // EAD1 jmp 0xead7
        },
        0xEAD4 => {
            m.mark(0xEAD4);
            m.ax = 0x148; // EAD4 mov ax, 0x148
            continue :sw 0xEAD7; // falls through
        },
        0xEAD7 => {
            m.mark(0xEAD7);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), m.ax)); // EAD7 add word ptr [bp - 4], ax
            m.ax = m.rw(0x9356); // EADA mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // EADD cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xEAE5; // EAE0 jle 0xeae5
            continue :sw 0xEBDD; // EAE2 jmp 0xebdd
        },
        0xEAE5 => {
            m.mark(0xEAE5);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x1F4)); // EAE5 add word ptr [bp - 2], 0x1f4
            m.bx = m.rw(m.bp +% 0x000A); // EAEA mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // EAED inc byte ptr [bx]
            continue :sw 0xEBDD; // EAEF jmp 0xebdd
        },
        0xEAF2 => {
            m.mark(0xEAF2);
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // EAF2 cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xEB12; // EAF7 je 0xeb12
            m.ax = m.rw(0xA272); // EAF9 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // EAFC cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xEB0B; // EAFF jg 0xeb0b
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xFA)); // EB01 add word ptr [bp - 2], 0xfa
            m.bx = m.rw(m.bp +% 0x000A); // EB06 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // EB09 inc byte ptr [bx]
            continue :sw 0xEB0B; // falls through
        },
        0xEB0B => {
            m.mark(0xEB0B);
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // EB0B inc word ptr [bp - 6]
            continue :sw 0xEBA0; // EB0E jmp 0xeba0
        },
        0xEB12 => {
            m.mark(0xEB12);
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // EB12 cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xEB1C; // EB17 je 0xeb1c
            continue :sw 0xEBDD; // EB19 jmp 0xebdd
        },
        0xEB1C => {
            m.mark(0xEB1C);
            m.si = m.di +% 0x00B0; // EB1C lea si, [di + 0xb0]
            m.bx = m.si; // EB20 mov bx, si
            m.setAl(m.rb(0xA03E)); // EB22 mov al, byte ptr [0xa03e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // EB25 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // EB27 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0BB4)); // EB29 mov al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // EB2D mov bx, si
            m.setCl(m.rb(0xA03F)); // EB2F mov cl, byte ptr [0xa03f]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // EB33 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // EB35 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // EB37 or al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // EB3B mov bx, si
            m.setCl(m.rb(0xA03C)); // EB3D mov cl, byte ptr [0xa03c]
            m.bx = m.sub(u16, m.bx, m.cx); // EB41 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // EB43 or al, byte ptr [bx + 0xab6]
            m.bx = m.si; // EB47 mov bx, si
            m.setCl(m.rb(0xA03D)); // EB49 mov cl, byte ptr [0xa03d]
            m.bx = m.sub(u16, m.bx, m.cx); // EB4D sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // EB4F or al, byte ptr [bx + 0xab6]
            m.bx = m.si; // EB53 mov bx, si
            m.setCl(m.rb(0xA03B)); // EB55 mov cl, byte ptr [0xa03b]
            m.bx = m.sub(u16, m.bx, m.cx); // EB59 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // EB5B or al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // EB5F mov bx, si
            m.setCl(m.rb(0xA03A)); // EB61 mov cl, byte ptr [0xa03a]
            m.bx = m.sub(u16, m.bx, m.cx); // EB65 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // EB67 or al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // EB6B mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // EB6D sub bx, word ptr [bp - 0xc]
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // EB70 or al, byte ptr [bx + 0xbb4]
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // EB74 or al, byte ptr [bx + 0xab6]
            m.bx = m.di; // EB78 mov bx, di
            m.setCl(m.rb(0xA041)); // EB7A mov cl, byte ptr [0xa041]
            m.bx = m.sub(u16, m.bx, m.cx); // EB7E sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0CFF))); // EB80 or al, byte ptr [bx + 0xcff]
            if (m.zf) continue :sw 0xEBDD; // EB84 je 0xebdd
            m.push(0x12); // EB86 push 0x12
            m.push(m.di); // EB88 push di
            m.far(.att_4cec, 0xEB89); // EB89 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EB8E or ax, ax
            if (m.sf == m.of) continue :sw 0xEBDD; // EB90 jge 0xebdd
            m.ax = m.rw(0xA272); // EB92 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // EB95 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xEB9D; // EB98 jg 0xeb9d
            continue :sw 0xEAE5; // EB9A jmp 0xeae5
        },
        0xEB9D => {
            m.mark(0xEB9D);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // EB9D inc word ptr [bp - 8]
            continue :sw 0xEBA0; // falls through
        },
        0xEBA0 => {
            m.mark(0xEBA0);
            m.setAl(m.xor(u8, m.al(), m.al())); // EBA0 xor al, al
            m.wb(0xA04A, m.al()); // EBA2 mov byte ptr [0xa04a], al
            m.wb(m.di +% 0x9EF6, m.al()); // EBA5 mov byte ptr [di - 0x610a], al
            m.wb(m.bp +% 0xFFEE, m.al()); // EBA9 mov byte ptr [bp - 0x12], al
            m.setAl(m.rb(m.di +% 0x9EFE)); // EBAC mov al, byte ptr [di - 0x6102]
            m.cbw(); // EBB0 cbw
            m.si = m.ax; // EBB1 mov si, ax
            m.cmp(u16, m.ax, 0x8); // EBB3 cmp ax, 8
            if (m.zf or m.sf != m.of) continue :sw 0xEBF0; // EBB6 jle 0xebf0
            m.cmp(u16, m.ax, 0xD); // EBB8 cmp ax, 0xd
            if (m.sf == m.of) continue :sw 0xEC3B; // EBBB jge 0xec3b
            m.setAl(m.rb(m.si +% 0x128C)); // EBBD mov al, byte ptr [si + 0x128c]
            m.cbw(); // EBC1 cbw
            m.push(m.ax); // EBC2 push ax
            m.ax = m.di +% 0x0008; // EBC3 lea ax, [di + 8]
            m.push(m.ax); // EBC6 push ax
            m.far(.att_4cec, 0xEBC7); // EBC7 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EBCC or ax, ax
            if (m.sf == m.of) continue :sw 0xEC3B; // EBCE jge 0xec3b
            continue :sw 0xEBD0; // falls through
        },
        0xEBD0 => {
            m.mark(0xEBD0);
            m.ax = m.di; // EBD0 mov ax, di
            m.wb(0xA04A, m.al()); // EBD2 mov byte ptr [0xa04a], al
            m.wb(m.di +% 0x9EF6, 0x9); // EBD5 mov byte ptr [di - 0x610a], 9
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // EBDA inc word ptr [bp - 8]
            continue :sw 0xEBDD; // falls through
        },
        0xEBDD => {
            m.mark(0xEBDD);
            m.setAl(m.rb(0xA04B)); // EBDD mov al, byte ptr [0xa04b]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // EBE0 sub ah, ah
            m.di = m.ax; // EBE2 mov di, ax
            m.cmp(u16, m.di, 0x62); // EBE4 cmp di, 0x62
            if (!m.zf and m.sf == m.of) continue :sw 0xEBEC; // EBE7 jg 0xebec
            continue :sw 0xEFBA; // EBE9 jmp 0xefba
        },
        0xEBEC => {
            m.mark(0xEBEC);
            continue :sw 0xF13B; // EBEC jmp 0xf13b
        },
        0xEBF0 => {
            m.mark(0xEBF0);
            m.cmp(u16, m.si, 0x8); // EBF0 cmp si, 8
            if (!m.zf) continue :sw 0xEC1C; // EBF3 jne 0xec1c
            m.push(0x6); // EBF5 push 6
            m.ax = m.di +% 0x0008; // EBF7 lea ax, [di + 8]
            m.push(m.ax); // EBFA push ax
            m.far(.att_4cec, 0xEBFB); // EBFB lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EC00 or ax, ax
            if (m.sf == m.of) continue :sw 0xEC3B; // EC02 jge 0xec3b
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // EC04 add word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // EC08 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // EC0B cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xEC3B; // EC0E jge 0xec3b
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // EC10 add word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // EC15 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // EC18 inc byte ptr [bx]
            continue :sw 0xEC3B; // EC1A jmp 0xec3b
        },
        0xEC1C => {
            m.mark(0xEC1C);
            m.cmp(u16, m.si, 0x1); // EC1C cmp si, 1
            if (!m.zf and m.sf == m.of) continue :sw 0xEC32; // EC1F jg 0xec32
            m.push(0x9); // EC21 push 9
            m.ax = m.di +% 0x0008; // EC23 lea ax, [di + 8]
            m.push(m.ax); // EC26 push ax
            m.far(.att_4cec, 0xEC27); // EC27 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EC2C or ax, ax
            if (m.sf != m.of) continue :sw 0xEC3B; // EC2E jl 0xec3b
            continue :sw 0xEC37; // EC30 jmp 0xec37
        },
        0xEC32 => {
            m.mark(0xEC32);
            m.cmp(u16, m.si, 0x7); // EC32 cmp si, 7
            if (m.sf == m.of) continue :sw 0xEC3B; // EC35 jge 0xec3b
            continue :sw 0xEC37; // falls through
        },
        0xEC37 => {
            m.mark(0xEC37);
            m.wb(m.bp +% 0xFFEE, 0x1); // EC37 mov byte ptr [bp - 0x12], 1
            continue :sw 0xEC3B; // falls through
        },
        0xEC3B => {
            m.mark(0xEC3B);
            m.setAl(m.rb(m.di +% 0x9F02)); // EC3B mov al, byte ptr [di - 0x60fe]
            m.cbw(); // EC3F cbw
            m.si = m.ax; // EC40 mov si, ax
            m.cmp(u16, m.si, 0x8); // EC42 cmp si, 8
            if (m.zf or m.sf != m.of) continue :sw 0xEC62; // EC45 jle 0xec62
            m.cmp(u16, m.si, 0xD); // EC47 cmp si, 0xd
            if (m.sf == m.of) continue :sw 0xECB3; // EC4A jge 0xecb3
            m.setAl(m.rb(m.si +% 0x128C)); // EC4C mov al, byte ptr [si + 0x128c]
            m.cbw(); // EC50 cbw
            m.push(m.ax); // EC51 push ax
            m.ax = m.di +% 0x000C; // EC52 lea ax, [di + 0xc]
            m.push(m.ax); // EC55 push ax
            m.far(.att_4cec, 0xEC56); // EC56 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EC5B or ax, ax
            if (m.sf == m.of) continue :sw 0xECB3; // EC5D jge 0xecb3
            continue :sw 0xEBD0; // EC5F jmp 0xebd0
        },
        0xEC62 => {
            m.mark(0xEC62);
            m.cmp(u16, m.si, 0x8); // EC62 cmp si, 8
            if (!m.zf) continue :sw 0xEC8E; // EC65 jne 0xec8e
            m.push(0x6); // EC67 push 6
            m.ax = m.di +% 0x000C; // EC69 lea ax, [di + 0xc]
            m.push(m.ax); // EC6C push ax
            m.far(.att_4cec, 0xEC6D); // EC6D lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EC72 or ax, ax
            if (m.sf == m.of) continue :sw 0xECB3; // EC74 jge 0xecb3
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // EC76 add word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // EC7A mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // EC7D cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xECB3; // EC80 jge 0xecb3
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // EC82 add word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // EC87 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // EC8A inc byte ptr [bx]
            continue :sw 0xECB3; // EC8C jmp 0xecb3
        },
        0xEC8E => {
            m.mark(0xEC8E);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // EC8E cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xECB3; // EC92 jne 0xecb3
            m.cmp(u16, m.si, 0x1); // EC94 cmp si, 1
            if (!m.zf and m.sf == m.of) continue :sw 0xECAA; // EC97 jg 0xecaa
            m.push(0x9); // EC99 push 9
            m.ax = m.di +% 0x000C; // EC9B lea ax, [di + 0xc]
            m.push(m.ax); // EC9E push ax
            m.far(.att_4cec, 0xEC9F); // EC9F lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // ECA4 or ax, ax
            if (m.sf != m.of) continue :sw 0xECB3; // ECA6 jl 0xecb3
            continue :sw 0xECAF; // ECA8 jmp 0xecaf
        },
        0xECAA => {
            m.mark(0xECAA);
            m.cmp(u16, m.si, 0x7); // ECAA cmp si, 7
            if (m.sf == m.of) continue :sw 0xECB3; // ECAD jge 0xecb3
            continue :sw 0xECAF; // falls through
        },
        0xECAF => {
            m.mark(0xECAF);
            m.wb(m.bp +% 0xFFEE, 0x1); // ECAF mov byte ptr [bp - 0x12], 1
            continue :sw 0xECB3; // falls through
        },
        0xECB3 => {
            m.mark(0xECB3);
            m.setAl(m.rb(m.di +% 0x9EEE)); // ECB3 mov al, byte ptr [di - 0x6112]
            m.cbw(); // ECB7 cbw
            m.si = m.ax; // ECB8 mov si, ax
            m.cmp(u16, m.si, 0x8); // ECBA cmp si, 8
            if (m.zf or m.sf != m.of) continue :sw 0xECDA; // ECBD jle 0xecda
            m.cmp(u16, m.si, 0xD); // ECBF cmp si, 0xd
            if (m.sf == m.of) continue :sw 0xED2B; // ECC2 jge 0xed2b
            m.setAl(m.rb(m.si +% 0x128C)); // ECC4 mov al, byte ptr [si + 0x128c]
            m.cbw(); // ECC8 cbw
            m.push(m.ax); // ECC9 push ax
            m.ax = m.di +% 0xFFF8; // ECCA lea ax, [di - 8]
            m.push(m.ax); // ECCD push ax
            m.far(.att_4cec, 0xECCE); // ECCE lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // ECD3 or ax, ax
            if (m.sf == m.of) continue :sw 0xED2B; // ECD5 jge 0xed2b
            continue :sw 0xEBD0; // ECD7 jmp 0xebd0
        },
        0xECDA => {
            m.mark(0xECDA);
            m.cmp(u16, m.si, 0x8); // ECDA cmp si, 8
            if (!m.zf) continue :sw 0xED06; // ECDD jne 0xed06
            m.push(0x6); // ECDF push 6
            m.ax = m.di +% 0xFFF8; // ECE1 lea ax, [di - 8]
            m.push(m.ax); // ECE4 push ax
            m.far(.att_4cec, 0xECE5); // ECE5 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // ECEA or ax, ax
            if (m.sf == m.of) continue :sw 0xED2B; // ECEC jge 0xed2b
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // ECEE add word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // ECF2 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // ECF5 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xED2B; // ECF8 jge 0xed2b
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // ECFA add word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // ECFF mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // ED02 inc byte ptr [bx]
            continue :sw 0xED2B; // ED04 jmp 0xed2b
        },
        0xED06 => {
            m.mark(0xED06);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // ED06 cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xED2B; // ED0A jne 0xed2b
            m.cmp(u16, m.si, 0x1); // ED0C cmp si, 1
            if (!m.zf and m.sf == m.of) continue :sw 0xED22; // ED0F jg 0xed22
            m.push(0x9); // ED11 push 9
            m.ax = m.di +% 0xFFF8; // ED13 lea ax, [di - 8]
            m.push(m.ax); // ED16 push ax
            m.far(.att_4cec, 0xED17); // ED17 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // ED1C or ax, ax
            if (m.sf != m.of) continue :sw 0xED2B; // ED1E jl 0xed2b
            continue :sw 0xED27; // ED20 jmp 0xed27
        },
        0xED22 => {
            m.mark(0xED22);
            m.cmp(u16, m.si, 0x7); // ED22 cmp si, 7
            if (m.sf == m.of) continue :sw 0xED2B; // ED25 jge 0xed2b
            continue :sw 0xED27; // falls through
        },
        0xED27 => {
            m.mark(0xED27);
            m.wb(m.bp +% 0xFFEE, 0x1); // ED27 mov byte ptr [bp - 0x12], 1
            continue :sw 0xED2B; // falls through
        },
        0xED2B => {
            m.mark(0xED2B);
            m.setAl(m.rb(m.di +% 0x9EEA)); // ED2B mov al, byte ptr [di - 0x6116]
            m.cbw(); // ED2F cbw
            m.si = m.ax; // ED30 mov si, ax
            m.cmp(u16, m.si, 0x8); // ED32 cmp si, 8
            if (m.zf or m.sf != m.of) continue :sw 0xED52; // ED35 jle 0xed52
            m.cmp(u16, m.si, 0xD); // ED37 cmp si, 0xd
            if (m.sf == m.of) continue :sw 0xEDA3; // ED3A jge 0xeda3
            m.setAl(m.rb(m.si +% 0x128C)); // ED3C mov al, byte ptr [si + 0x128c]
            m.cbw(); // ED40 cbw
            m.push(m.ax); // ED41 push ax
            m.ax = m.di +% 0xFFF4; // ED42 lea ax, [di - 0xc]
            m.push(m.ax); // ED45 push ax
            m.far(.att_4cec, 0xED46); // ED46 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // ED4B or ax, ax
            if (m.sf == m.of) continue :sw 0xEDA3; // ED4D jge 0xeda3
            continue :sw 0xEBD0; // ED4F jmp 0xebd0
        },
        0xED52 => {
            m.mark(0xED52);
            m.cmp(u16, m.si, 0x8); // ED52 cmp si, 8
            if (!m.zf) continue :sw 0xED7E; // ED55 jne 0xed7e
            m.push(0x6); // ED57 push 6
            m.ax = m.di +% 0xFFF4; // ED59 lea ax, [di - 0xc]
            m.push(m.ax); // ED5C push ax
            m.far(.att_4cec, 0xED5D); // ED5D lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // ED62 or ax, ax
            if (m.sf == m.of) continue :sw 0xEDA3; // ED64 jge 0xeda3
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // ED66 add word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // ED6A mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // ED6D cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xEDA3; // ED70 jge 0xeda3
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // ED72 add word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // ED77 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // ED7A inc byte ptr [bx]
            continue :sw 0xEDA3; // ED7C jmp 0xeda3
        },
        0xED7E => {
            m.mark(0xED7E);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // ED7E cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xEDA3; // ED82 jne 0xeda3
            m.cmp(u16, m.si, 0x1); // ED84 cmp si, 1
            if (!m.zf and m.sf == m.of) continue :sw 0xED9A; // ED87 jg 0xed9a
            m.push(0x9); // ED89 push 9
            m.ax = m.di +% 0xFFF4; // ED8B lea ax, [di - 0xc]
            m.push(m.ax); // ED8E push ax
            m.far(.att_4cec, 0xED8F); // ED8F lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // ED94 or ax, ax
            if (m.sf != m.of) continue :sw 0xEDA3; // ED96 jl 0xeda3
            continue :sw 0xED9F; // ED98 jmp 0xed9f
        },
        0xED9A => {
            m.mark(0xED9A);
            m.cmp(u16, m.si, 0x7); // ED9A cmp si, 7
            if (m.sf == m.of) continue :sw 0xEDA3; // ED9D jge 0xeda3
            continue :sw 0xED9F; // falls through
        },
        0xED9F => {
            m.mark(0xED9F);
            m.wb(m.bp +% 0xFFEE, 0x1); // ED9F mov byte ptr [bp - 0x12], 1
            continue :sw 0xEDA3; // falls through
        },
        0xEDA3 => {
            m.mark(0xEDA3);
            m.setAl(m.rb(m.di +% 0x9EE3)); // EDA3 mov al, byte ptr [di - 0x611d]
            m.cbw(); // EDA7 cbw
            m.si = m.ax; // EDA8 mov si, ax
            m.cmp(u16, m.si, 0x8); // EDAA cmp si, 8
            if (m.zf or m.sf != m.of) continue :sw 0xEDCA; // EDAD jle 0xedca
            m.cmp(u16, m.si, 0xD); // EDAF cmp si, 0xd
            if (m.sf == m.of) continue :sw 0xEE1B; // EDB2 jge 0xee1b
            m.setAl(m.rb(m.si +% 0x128C)); // EDB4 mov al, byte ptr [si + 0x128c]
            m.cbw(); // EDB8 cbw
            m.push(m.ax); // EDB9 push ax
            m.ax = m.di +% 0xFFED; // EDBA lea ax, [di - 0x13]
            m.push(m.ax); // EDBD push ax
            m.far(.att_4cec, 0xEDBE); // EDBE lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EDC3 or ax, ax
            if (m.sf == m.of) continue :sw 0xEE1B; // EDC5 jge 0xee1b
            continue :sw 0xEBD0; // EDC7 jmp 0xebd0
        },
        0xEDCA => {
            m.mark(0xEDCA);
            m.cmp(u16, m.si, 0x8); // EDCA cmp si, 8
            if (!m.zf) continue :sw 0xEDF6; // EDCD jne 0xedf6
            m.push(0x6); // EDCF push 6
            m.ax = m.di +% 0xFFED; // EDD1 lea ax, [di - 0x13]
            m.push(m.ax); // EDD4 push ax
            m.far(.att_4cec, 0xEDD5); // EDD5 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EDDA or ax, ax
            if (m.sf == m.of) continue :sw 0xEE1B; // EDDC jge 0xee1b
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // EDDE add word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // EDE2 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // EDE5 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xEE1B; // EDE8 jge 0xee1b
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // EDEA add word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // EDEF mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // EDF2 inc byte ptr [bx]
            continue :sw 0xEE1B; // EDF4 jmp 0xee1b
        },
        0xEDF6 => {
            m.mark(0xEDF6);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // EDF6 cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xEE1B; // EDFA jne 0xee1b
            m.cmp(u16, m.si, 0x1); // EDFC cmp si, 1
            if (!m.zf and m.sf == m.of) continue :sw 0xEE12; // EDFF jg 0xee12
            m.push(0x9); // EE01 push 9
            m.ax = m.di +% 0xFFED; // EE03 lea ax, [di - 0x13]
            m.push(m.ax); // EE06 push ax
            m.far(.att_4cec, 0xEE07); // EE07 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EE0C or ax, ax
            if (m.sf != m.of) continue :sw 0xEE1B; // EE0E jl 0xee1b
            continue :sw 0xEE17; // EE10 jmp 0xee17
        },
        0xEE12 => {
            m.mark(0xEE12);
            m.cmp(u16, m.si, 0x7); // EE12 cmp si, 7
            if (m.sf == m.of) continue :sw 0xEE1B; // EE15 jge 0xee1b
            continue :sw 0xEE17; // falls through
        },
        0xEE17 => {
            m.mark(0xEE17);
            m.wb(m.bp +% 0xFFEE, 0x1); // EE17 mov byte ptr [bp - 0x12], 1
            continue :sw 0xEE1B; // falls through
        },
        0xEE1B => {
            m.mark(0xEE1B);
            m.setAl(m.rb(m.di +% 0x9EE1)); // EE1B mov al, byte ptr [di - 0x611f]
            m.cbw(); // EE1F cbw
            m.si = m.ax; // EE20 mov si, ax
            m.cmp(u16, m.si, 0x8); // EE22 cmp si, 8
            if (m.zf or m.sf != m.of) continue :sw 0xEE42; // EE25 jle 0xee42
            m.cmp(u16, m.si, 0xD); // EE27 cmp si, 0xd
            if (m.sf == m.of) continue :sw 0xEE93; // EE2A jge 0xee93
            m.setAl(m.rb(m.si +% 0x128C)); // EE2C mov al, byte ptr [si + 0x128c]
            m.cbw(); // EE30 cbw
            m.push(m.ax); // EE31 push ax
            m.ax = m.di +% 0xFFEB; // EE32 lea ax, [di - 0x15]
            m.push(m.ax); // EE35 push ax
            m.far(.att_4cec, 0xEE36); // EE36 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EE3B or ax, ax
            if (m.sf == m.of) continue :sw 0xEE93; // EE3D jge 0xee93
            continue :sw 0xEBD0; // EE3F jmp 0xebd0
        },
        0xEE42 => {
            m.mark(0xEE42);
            m.cmp(u16, m.si, 0x8); // EE42 cmp si, 8
            if (!m.zf) continue :sw 0xEE6E; // EE45 jne 0xee6e
            m.push(0x6); // EE47 push 6
            m.ax = m.di +% 0xFFEB; // EE49 lea ax, [di - 0x15]
            m.push(m.ax); // EE4C push ax
            m.far(.att_4cec, 0xEE4D); // EE4D lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EE52 or ax, ax
            if (m.sf == m.of) continue :sw 0xEE93; // EE54 jge 0xee93
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // EE56 add word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // EE5A mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // EE5D cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xEE93; // EE60 jge 0xee93
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // EE62 add word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // EE67 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // EE6A inc byte ptr [bx]
            continue :sw 0xEE93; // EE6C jmp 0xee93
        },
        0xEE6E => {
            m.mark(0xEE6E);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // EE6E cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xEE93; // EE72 jne 0xee93
            m.cmp(u16, m.si, 0x1); // EE74 cmp si, 1
            if (!m.zf and m.sf == m.of) continue :sw 0xEE8A; // EE77 jg 0xee8a
            m.push(0x9); // EE79 push 9
            m.ax = m.di +% 0xFFEB; // EE7B lea ax, [di - 0x15]
            m.push(m.ax); // EE7E push ax
            m.far(.att_4cec, 0xEE7F); // EE7F lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EE84 or ax, ax
            if (m.sf != m.of) continue :sw 0xEE93; // EE86 jl 0xee93
            continue :sw 0xEE8F; // EE88 jmp 0xee8f
        },
        0xEE8A => {
            m.mark(0xEE8A);
            m.cmp(u16, m.si, 0x7); // EE8A cmp si, 7
            if (m.sf == m.of) continue :sw 0xEE93; // EE8D jge 0xee93
            continue :sw 0xEE8F; // falls through
        },
        0xEE8F => {
            m.mark(0xEE8F);
            m.wb(m.bp +% 0xFFEE, 0x1); // EE8F mov byte ptr [bp - 0x12], 1
            continue :sw 0xEE93; // falls through
        },
        0xEE93 => {
            m.mark(0xEE93);
            m.cmp(u16, m.di, 0x47); // EE93 cmp di, 0x47
            if (m.sf != m.of) continue :sw 0xEEA2; // EE96 jl 0xeea2
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // EE98 cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xEEA2; // EE9C jne 0xeea2
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x24)); // EE9E add word ptr [bp - 2], 0x24
            continue :sw 0xEEA2; // falls through
        },
        0xEEA2 => {
            m.mark(0xEEA2);
            m.setAl(m.rb(m.di +% 0x9F09)); // EEA2 mov al, byte ptr [di - 0x60f7]
            m.cbw(); // EEA6 cbw
            m.si = m.ax; // EEA7 mov si, ax
            m.cmp(u16, m.si, 0x8); // EEA9 cmp si, 8
            if (m.zf or m.sf != m.of) continue :sw 0xEECA; // EEAC jle 0xeeca
            m.cmp(u16, m.si, 0xD); // EEAE cmp si, 0xd
            if (m.sf == m.of) continue :sw 0xEF1B; // EEB1 jge 0xef1b
            m.setAl(m.rb(m.si +% 0x128C)); // EEB3 mov al, byte ptr [si + 0x128c]
            m.cbw(); // EEB7 cbw
            m.push(m.ax); // EEB8 push ax
            m.ax = m.di +% 0x0013; // EEB9 lea ax, [di + 0x13]
            m.push(m.ax); // EEBC push ax
            m.far(.att_4cec, 0xEEBD); // EEBD lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EEC2 or ax, ax
            if (m.sf == m.of) continue :sw 0xEF1B; // EEC4 jge 0xef1b
            continue :sw 0xEBD0; // EEC6 jmp 0xebd0
        },
        0xEECA => {
            m.mark(0xEECA);
            m.cmp(u16, m.si, 0x8); // EECA cmp si, 8
            if (!m.zf) continue :sw 0xEEF6; // EECD jne 0xeef6
            m.push(0x6); // EECF push 6
            m.ax = m.di +% 0x0013; // EED1 lea ax, [di + 0x13]
            m.push(m.ax); // EED4 push ax
            m.far(.att_4cec, 0xEED5); // EED5 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EEDA or ax, ax
            if (m.sf == m.of) continue :sw 0xEF1B; // EEDC jge 0xef1b
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // EEDE add word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // EEE2 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // EEE5 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xEF1B; // EEE8 jge 0xef1b
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // EEEA add word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // EEEF mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // EEF2 inc byte ptr [bx]
            continue :sw 0xEF1B; // EEF4 jmp 0xef1b
        },
        0xEEF6 => {
            m.mark(0xEEF6);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // EEF6 cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xEF1B; // EEFA jne 0xef1b
            m.cmp(u16, m.si, 0x1); // EEFC cmp si, 1
            if (!m.zf and m.sf == m.of) continue :sw 0xEF12; // EEFF jg 0xef12
            m.push(0x9); // EF01 push 9
            m.ax = m.di +% 0x0013; // EF03 lea ax, [di + 0x13]
            m.push(m.ax); // EF06 push ax
            m.far(.att_4cec, 0xEF07); // EF07 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EF0C or ax, ax
            if (m.sf != m.of) continue :sw 0xEF1B; // EF0E jl 0xef1b
            continue :sw 0xEF17; // EF10 jmp 0xef17
        },
        0xEF12 => {
            m.mark(0xEF12);
            m.cmp(u16, m.si, 0x7); // EF12 cmp si, 7
            if (m.sf == m.of) continue :sw 0xEF1B; // EF15 jge 0xef1b
            continue :sw 0xEF17; // falls through
        },
        0xEF17 => {
            m.mark(0xEF17);
            m.wb(m.bp +% 0xFFEE, 0x1); // EF17 mov byte ptr [bp - 0x12], 1
            continue :sw 0xEF1B; // falls through
        },
        0xEF1B => {
            m.mark(0xEF1B);
            m.setAl(m.rb(m.di +% 0x9F0B)); // EF1B mov al, byte ptr [di - 0x60f5]
            m.cbw(); // EF1F cbw
            m.si = m.ax; // EF20 mov si, ax
            m.cmp(u16, m.si, 0x8); // EF22 cmp si, 8
            if (m.zf or m.sf != m.of) continue :sw 0xEF42; // EF25 jle 0xef42
            m.cmp(u16, m.si, 0xD); // EF27 cmp si, 0xd
            if (m.sf == m.of) continue :sw 0xEF93; // EF2A jge 0xef93
            m.setAl(m.rb(m.si +% 0x128C)); // EF2C mov al, byte ptr [si + 0x128c]
            m.cbw(); // EF30 cbw
            m.push(m.ax); // EF31 push ax
            m.ax = m.di +% 0x0015; // EF32 lea ax, [di + 0x15]
            m.push(m.ax); // EF35 push ax
            m.far(.att_4cec, 0xEF36); // EF36 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EF3B or ax, ax
            if (m.sf == m.of) continue :sw 0xEF93; // EF3D jge 0xef93
            continue :sw 0xEBD0; // EF3F jmp 0xebd0
        },
        0xEF42 => {
            m.mark(0xEF42);
            m.cmp(u16, m.si, 0x8); // EF42 cmp si, 8
            if (!m.zf) continue :sw 0xEF6E; // EF45 jne 0xef6e
            m.push(0x6); // EF47 push 6
            m.ax = m.di +% 0x0015; // EF49 lea ax, [di + 0x15]
            m.push(m.ax); // EF4C push ax
            m.far(.att_4cec, 0xEF4D); // EF4D lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EF52 or ax, ax
            if (m.sf == m.of) continue :sw 0xEF93; // EF54 jge 0xef93
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // EF56 add word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // EF5A mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // EF5D cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xEF93; // EF60 jge 0xef93
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // EF62 add word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // EF67 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // EF6A inc byte ptr [bx]
            continue :sw 0xEF93; // EF6C jmp 0xef93
        },
        0xEF6E => {
            m.mark(0xEF6E);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // EF6E cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xEF93; // EF72 jne 0xef93
            m.cmp(u16, m.si, 0x1); // EF74 cmp si, 1
            if (!m.zf and m.sf == m.of) continue :sw 0xEF8A; // EF77 jg 0xef8a
            m.push(0x9); // EF79 push 9
            m.ax = m.di +% 0x0015; // EF7B lea ax, [di + 0x15]
            m.push(m.ax); // EF7E push ax
            m.far(.att_4cec, 0xEF7F); // EF7F lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // EF84 or ax, ax
            if (m.sf != m.of) continue :sw 0xEF93; // EF86 jl 0xef93
            continue :sw 0xEF8F; // EF88 jmp 0xef8f
        },
        0xEF8A => {
            m.mark(0xEF8A);
            m.cmp(u16, m.si, 0x7); // EF8A cmp si, 7
            if (m.sf == m.of) continue :sw 0xEF93; // EF8D jge 0xef93
            continue :sw 0xEF8F; // falls through
        },
        0xEF8F => {
            m.mark(0xEF8F);
            m.wb(m.bp +% 0xFFEE, 0x1); // EF8F mov byte ptr [bp - 0x12], 1
            continue :sw 0xEF93; // falls through
        },
        0xEF93 => {
            m.mark(0xEF93);
            m.ax = m.di; // EF93 mov ax, di
            m.wb(0xA04A, m.al()); // EF95 mov byte ptr [0xa04a], al
            m.wb(m.di +% 0x9EF6, 0x9); // EF98 mov byte ptr [di - 0x610a], 9
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // EF9D cmp byte ptr [bp - 0x12], 0
            if (m.zf) continue :sw 0xEFA6; // EFA1 je 0xefa6
            continue :sw 0xEBDD; // EFA3 jmp 0xebdd
        },
        0xEFA6 => {
            m.mark(0xEFA6);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x15E)); // EFA6 add word ptr [bp - 4], 0x15e
            m.ax = m.rw(0x9356); // EFAB mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // EFAE cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xEFB6; // EFB1 jl 0xefb6
            continue :sw 0xEBDD; // EFB3 jmp 0xebdd
        },
        0xEFB6 => {
            m.mark(0xEFB6);
            continue :sw 0xEAE5; // EFB6 jmp 0xeae5
        },
        0xEFBA => {
            m.mark(0xEFBA);
            m.cmp(u8, m.rb(m.di +% 0xA164), 0x0); // EFBA cmp byte ptr [di - 0x5e9c], 0
            if (!m.zf) continue :sw 0xEFC4; // EFBF jne 0xefc4
            continue :sw 0xF050; // EFC1 jmp 0xf050
        },
        0xEFC4 => {
            m.mark(0xEFC4);
            m.setAl(m.rb(m.di +% 0xA164)); // EFC4 mov al, byte ptr [di - 0x5e9c]
            m.cbw(); // EFC8 cbw
            m.bx = m.ax; // EFC9 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x047E)); // EFCB mov al, byte ptr [bx + 0x47e]
            m.wb(m.bp +% 0xFFF2, m.al()); // EFCF mov byte ptr [bp - 0xe], al
            m.setAl(m.rb(m.bx +% 0x0490)); // EFD2 mov al, byte ptr [bx + 0x490]
            m.cbw(); // EFD6 cbw
            m.si = m.ax; // EFD7 mov si, ax
            continue :sw 0xEFD9; // falls through
        },
        0xEFD9 => {
            m.mark(0xEFD9);
            m.di = m.add(u16, m.di, m.si); // EFD9 add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // EFDB cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xEFD9; // EFE0 je 0xefd9
            m.si = m.di; // EFE2 mov si, di
            m.setAl(m.rb(0xA04B)); // EFE4 mov al, byte ptr [0xa04b]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // EFE7 sub ah, ah
            m.di = m.ax; // EFE9 mov di, ax
            m.cx = m.di; // EFEB mov cx, di
            m.setAl(m.rb(m.si +% 0x9EF6)); // EFED mov al, byte ptr [si - 0x610a]
            m.cbw(); // EFF1 cbw
            m.bx = m.ax; // EFF2 mov bx, ax
            m.setAl(m.rb(m.bp +% 0xFFF2)); // EFF4 mov al, byte ptr [bp - 0xe]
            m.@"test"(u8, m.rb(m.bx +% 0x0470), m.al()); // EFF7 test byte ptr [bx + 0x470], al
            if (m.zf) continue :sw 0xF050; // EFFB je 0xf050
            m.bx = m.cx; // EFFD mov bx, cx
            m.cmp(u8, m.rb(m.bx +% 0xA51C), m.ch()); // EFFF cmp byte ptr [bx - 0x5ae4], ch
            if (m.zf) continue :sw 0xF008; // F003 je 0xf008
            continue :sw 0xF55C; // F005 jmp 0xf55c
        },
        0xF008 => {
            m.mark(0xF008);
            m.push(0x12); // F008 push 0x12
            m.push(m.di); // F00A push di
            m.far(.att_4cec, 0xF00B); // F00B lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F010 or ax, ax
            if (m.sf != m.of) continue :sw 0xF017; // F012 jl 0xf017
            continue :sw 0xF13B; // F014 jmp 0xf13b
        },
        0xF017 => {
            m.mark(0xF017);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // F017 inc word ptr [bp - 8]
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // F01A cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xF024; // F01F je 0xf024
            continue :sw 0xF13B; // F021 jmp 0xf13b
        },
        0xF024 => {
            m.mark(0xF024);
            m.cmp(u8, m.rb(0x931B), 0x1); // F024 cmp byte ptr [0x931b], 1
            if (m.zf or m.sf != m.of) continue :sw 0xF032; // F029 jle 0xf032
            m.ax = 0x80; // F02B mov ax, 0x80
            continue :sw 0xF035; // F02E jmp 0xf035
        },
        0xF032 => {
            m.mark(0xF032);
            m.ax = 0x148; // F032 mov ax, 0x148
            continue :sw 0xF035; // falls through
        },
        0xF035 => {
            m.mark(0xF035);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), m.ax)); // F035 add word ptr [bp - 4], ax
            m.ax = m.rw(0x9356); // F038 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F03B cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xF043; // F03E jle 0xf043
            continue :sw 0xF13B; // F040 jmp 0xf13b
        },
        0xF043 => {
            m.mark(0xF043);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x1F4)); // F043 add word ptr [bp - 2], 0x1f4
            m.bx = m.rw(m.bp +% 0x000A); // F048 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // F04B inc byte ptr [bx]
            continue :sw 0xF13B; // F04D jmp 0xf13b
        },
        0xF050 => {
            m.mark(0xF050);
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // F050 cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xF070; // F055 je 0xf070
            m.ax = m.rw(0xA272); // F057 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F05A cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xF069; // F05D jg 0xf069
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xFA)); // F05F add word ptr [bp - 2], 0xfa
            m.bx = m.rw(m.bp +% 0x000A); // F064 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // F067 inc byte ptr [bx]
            continue :sw 0xF069; // falls through
        },
        0xF069 => {
            m.mark(0xF069);
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // F069 inc word ptr [bp - 6]
            continue :sw 0xF0FE; // F06C jmp 0xf0fe
        },
        0xF070 => {
            m.mark(0xF070);
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // F070 cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xF07A; // F075 je 0xf07a
            continue :sw 0xF13B; // F077 jmp 0xf13b
        },
        0xF07A => {
            m.mark(0xF07A);
            m.si = m.di +% 0x00B0; // F07A lea si, [di + 0xb0]
            m.bx = m.si; // F07E mov bx, si
            m.setAl(m.rb(0xA03E)); // F080 mov al, byte ptr [0xa03e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // F083 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // F085 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0BB4)); // F087 mov al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // F08B mov bx, si
            m.setCl(m.rb(0xA03F)); // F08D mov cl, byte ptr [0xa03f]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // F091 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // F093 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // F095 or al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // F099 mov bx, si
            m.setCl(m.rb(0xA03C)); // F09B mov cl, byte ptr [0xa03c]
            m.bx = m.sub(u16, m.bx, m.cx); // F09F sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // F0A1 or al, byte ptr [bx + 0xab6]
            m.bx = m.si; // F0A5 mov bx, si
            m.setCl(m.rb(0xA03D)); // F0A7 mov cl, byte ptr [0xa03d]
            m.bx = m.sub(u16, m.bx, m.cx); // F0AB sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // F0AD or al, byte ptr [bx + 0xab6]
            m.bx = m.si; // F0B1 mov bx, si
            m.setCl(m.rb(0xA03B)); // F0B3 mov cl, byte ptr [0xa03b]
            m.bx = m.sub(u16, m.bx, m.cx); // F0B7 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // F0B9 or al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // F0BD mov bx, si
            m.setCl(m.rb(0xA03A)); // F0BF mov cl, byte ptr [0xa03a]
            m.bx = m.sub(u16, m.bx, m.cx); // F0C3 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // F0C5 or al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // F0C9 mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // F0CB sub bx, word ptr [bp - 0xc]
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // F0CE or al, byte ptr [bx + 0xbb4]
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // F0D2 or al, byte ptr [bx + 0xab6]
            m.bx = m.di; // F0D6 mov bx, di
            m.setCl(m.rb(0xA041)); // F0D8 mov cl, byte ptr [0xa041]
            m.bx = m.sub(u16, m.bx, m.cx); // F0DC sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0CFF))); // F0DE or al, byte ptr [bx + 0xcff]
            if (m.zf) continue :sw 0xF13B; // F0E2 je 0xf13b
            m.push(0x12); // F0E4 push 0x12
            m.push(m.di); // F0E6 push di
            m.far(.att_4cec, 0xF0E7); // F0E7 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F0EC or ax, ax
            if (m.sf == m.of) continue :sw 0xF13B; // F0EE jge 0xf13b
            m.ax = m.rw(0xA272); // F0F0 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F0F3 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xF0FB; // F0F6 jg 0xf0fb
            continue :sw 0xF043; // F0F8 jmp 0xf043
        },
        0xF0FB => {
            m.mark(0xF0FB);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // F0FB inc word ptr [bp - 8]
            continue :sw 0xF0FE; // falls through
        },
        0xF0FE => {
            m.mark(0xF0FE);
            m.setAl(m.xor(u8, m.al(), m.al())); // F0FE xor al, al
            m.wb(0xA04B, m.al()); // F100 mov byte ptr [0xa04b], al
            m.wb(m.di +% 0x9EF6, m.al()); // F103 mov byte ptr [di - 0x610a], al
            m.wb(m.bp +% 0xFFEE, m.al()); // F107 mov byte ptr [bp - 0x12], al
            m.setAl(m.rb(m.di +% 0x9EFE)); // F10A mov al, byte ptr [di - 0x6102]
            m.cbw(); // F10E cbw
            m.si = m.ax; // F10F mov si, ax
            m.cmp(u16, m.ax, 0x8); // F111 cmp ax, 8
            if (m.zf or m.sf != m.of) continue :sw 0xF14E; // F114 jle 0xf14e
            m.cmp(u16, m.ax, 0xD); // F116 cmp ax, 0xd
            if (m.sf == m.of) continue :sw 0xF199; // F119 jge 0xf199
            m.setAl(m.rb(m.si +% 0x128C)); // F11B mov al, byte ptr [si + 0x128c]
            m.cbw(); // F11F cbw
            m.push(m.ax); // F120 push ax
            m.ax = m.di +% 0x0008; // F121 lea ax, [di + 8]
            m.push(m.ax); // F124 push ax
            m.far(.att_4cec, 0xF125); // F125 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F12A or ax, ax
            if (m.sf == m.of) continue :sw 0xF199; // F12C jge 0xf199
            continue :sw 0xF12E; // falls through
        },
        0xF12E => {
            m.mark(0xF12E);
            m.ax = m.di; // F12E mov ax, di
            m.wb(0xA04B, m.al()); // F130 mov byte ptr [0xa04b], al
            m.wb(m.di +% 0x9EF6, 0x9); // F133 mov byte ptr [di - 0x610a], 9
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // F138 inc word ptr [bp - 8]
            continue :sw 0xF13B; // falls through
        },
        0xF13B => {
            m.mark(0xF13B);
            m.setAl(m.rb(0xA04C)); // F13B mov al, byte ptr [0xa04c]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // F13E sub ah, ah
            m.di = m.ax; // F140 mov di, ax
            m.cmp(u16, m.di, 0x62); // F142 cmp di, 0x62
            if (!m.zf and m.sf == m.of) continue :sw 0xF14A; // F145 jg 0xf14a
            continue :sw 0xF518; // F147 jmp 0xf518
        },
        0xF14A => {
            m.mark(0xF14A);
            continue :sw 0xF788; // F14A jmp 0xf788
        },
        0xF14E => {
            m.mark(0xF14E);
            m.cmp(u16, m.si, 0x8); // F14E cmp si, 8
            if (!m.zf) continue :sw 0xF17A; // F151 jne 0xf17a
            m.push(0x6); // F153 push 6
            m.ax = m.di +% 0x0008; // F155 lea ax, [di + 8]
            m.push(m.ax); // F158 push ax
            m.far(.att_4cec, 0xF159); // F159 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F15E or ax, ax
            if (m.sf == m.of) continue :sw 0xF199; // F160 jge 0xf199
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // F162 add word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // F166 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F169 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xF199; // F16C jge 0xf199
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // F16E add word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // F173 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // F176 inc byte ptr [bx]
            continue :sw 0xF199; // F178 jmp 0xf199
        },
        0xF17A => {
            m.mark(0xF17A);
            m.cmp(u16, m.si, 0x1); // F17A cmp si, 1
            if (!m.zf and m.sf == m.of) continue :sw 0xF190; // F17D jg 0xf190
            m.push(0x9); // F17F push 9
            m.ax = m.di +% 0x0008; // F181 lea ax, [di + 8]
            m.push(m.ax); // F184 push ax
            m.far(.att_4cec, 0xF185); // F185 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F18A or ax, ax
            if (m.sf != m.of) continue :sw 0xF199; // F18C jl 0xf199
            continue :sw 0xF195; // F18E jmp 0xf195
        },
        0xF190 => {
            m.mark(0xF190);
            m.cmp(u16, m.si, 0x7); // F190 cmp si, 7
            if (m.sf == m.of) continue :sw 0xF199; // F193 jge 0xf199
            continue :sw 0xF195; // falls through
        },
        0xF195 => {
            m.mark(0xF195);
            m.wb(m.bp +% 0xFFEE, 0x1); // F195 mov byte ptr [bp - 0x12], 1
            continue :sw 0xF199; // falls through
        },
        0xF199 => {
            m.mark(0xF199);
            m.setAl(m.rb(m.di +% 0x9F02)); // F199 mov al, byte ptr [di - 0x60fe]
            m.cbw(); // F19D cbw
            m.si = m.ax; // F19E mov si, ax
            m.cmp(u16, m.si, 0x8); // F1A0 cmp si, 8
            if (m.zf or m.sf != m.of) continue :sw 0xF1C0; // F1A3 jle 0xf1c0
            m.cmp(u16, m.si, 0xD); // F1A5 cmp si, 0xd
            if (m.sf == m.of) continue :sw 0xF211; // F1A8 jge 0xf211
            m.setAl(m.rb(m.si +% 0x128C)); // F1AA mov al, byte ptr [si + 0x128c]
            m.cbw(); // F1AE cbw
            m.push(m.ax); // F1AF push ax
            m.ax = m.di +% 0x000C; // F1B0 lea ax, [di + 0xc]
            m.push(m.ax); // F1B3 push ax
            m.far(.att_4cec, 0xF1B4); // F1B4 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F1B9 or ax, ax
            if (m.sf == m.of) continue :sw 0xF211; // F1BB jge 0xf211
            continue :sw 0xF12E; // F1BD jmp 0xf12e
        },
        0xF1C0 => {
            m.mark(0xF1C0);
            m.cmp(u16, m.si, 0x8); // F1C0 cmp si, 8
            if (!m.zf) continue :sw 0xF1EC; // F1C3 jne 0xf1ec
            m.push(0x6); // F1C5 push 6
            m.ax = m.di +% 0x000C; // F1C7 lea ax, [di + 0xc]
            m.push(m.ax); // F1CA push ax
            m.far(.att_4cec, 0xF1CB); // F1CB lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F1D0 or ax, ax
            if (m.sf == m.of) continue :sw 0xF211; // F1D2 jge 0xf211
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // F1D4 add word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // F1D8 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F1DB cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xF211; // F1DE jge 0xf211
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // F1E0 add word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // F1E5 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // F1E8 inc byte ptr [bx]
            continue :sw 0xF211; // F1EA jmp 0xf211
        },
        0xF1EC => {
            m.mark(0xF1EC);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // F1EC cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xF211; // F1F0 jne 0xf211
            m.cmp(u16, m.si, 0x1); // F1F2 cmp si, 1
            if (!m.zf and m.sf == m.of) continue :sw 0xF208; // F1F5 jg 0xf208
            m.push(0x9); // F1F7 push 9
            m.ax = m.di +% 0x000C; // F1F9 lea ax, [di + 0xc]
            m.push(m.ax); // F1FC push ax
            m.far(.att_4cec, 0xF1FD); // F1FD lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F202 or ax, ax
            if (m.sf != m.of) continue :sw 0xF211; // F204 jl 0xf211
            continue :sw 0xF20D; // F206 jmp 0xf20d
        },
        0xF208 => {
            m.mark(0xF208);
            m.cmp(u16, m.si, 0x7); // F208 cmp si, 7
            if (m.sf == m.of) continue :sw 0xF211; // F20B jge 0xf211
            continue :sw 0xF20D; // falls through
        },
        0xF20D => {
            m.mark(0xF20D);
            m.wb(m.bp +% 0xFFEE, 0x1); // F20D mov byte ptr [bp - 0x12], 1
            continue :sw 0xF211; // falls through
        },
        0xF211 => {
            m.mark(0xF211);
            m.setAl(m.rb(m.di +% 0x9EEE)); // F211 mov al, byte ptr [di - 0x6112]
            m.cbw(); // F215 cbw
            m.si = m.ax; // F216 mov si, ax
            m.cmp(u16, m.si, 0x8); // F218 cmp si, 8
            if (m.zf or m.sf != m.of) continue :sw 0xF238; // F21B jle 0xf238
            m.cmp(u16, m.si, 0xD); // F21D cmp si, 0xd
            if (m.sf == m.of) continue :sw 0xF289; // F220 jge 0xf289
            m.setAl(m.rb(m.si +% 0x128C)); // F222 mov al, byte ptr [si + 0x128c]
            m.cbw(); // F226 cbw
            m.push(m.ax); // F227 push ax
            m.ax = m.di +% 0xFFF8; // F228 lea ax, [di - 8]
            m.push(m.ax); // F22B push ax
            m.far(.att_4cec, 0xF22C); // F22C lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F231 or ax, ax
            if (m.sf == m.of) continue :sw 0xF289; // F233 jge 0xf289
            continue :sw 0xF12E; // F235 jmp 0xf12e
        },
        0xF238 => {
            m.mark(0xF238);
            m.cmp(u16, m.si, 0x8); // F238 cmp si, 8
            if (!m.zf) continue :sw 0xF264; // F23B jne 0xf264
            m.push(0x6); // F23D push 6
            m.ax = m.di +% 0xFFF8; // F23F lea ax, [di - 8]
            m.push(m.ax); // F242 push ax
            m.far(.att_4cec, 0xF243); // F243 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F248 or ax, ax
            if (m.sf == m.of) continue :sw 0xF289; // F24A jge 0xf289
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // F24C add word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // F250 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F253 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xF289; // F256 jge 0xf289
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // F258 add word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // F25D mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // F260 inc byte ptr [bx]
            continue :sw 0xF289; // F262 jmp 0xf289
        },
        0xF264 => {
            m.mark(0xF264);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // F264 cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xF289; // F268 jne 0xf289
            m.cmp(u16, m.si, 0x1); // F26A cmp si, 1
            if (!m.zf and m.sf == m.of) continue :sw 0xF280; // F26D jg 0xf280
            m.push(0x9); // F26F push 9
            m.ax = m.di +% 0xFFF8; // F271 lea ax, [di - 8]
            m.push(m.ax); // F274 push ax
            m.far(.att_4cec, 0xF275); // F275 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F27A or ax, ax
            if (m.sf != m.of) continue :sw 0xF289; // F27C jl 0xf289
            continue :sw 0xF285; // F27E jmp 0xf285
        },
        0xF280 => {
            m.mark(0xF280);
            m.cmp(u16, m.si, 0x7); // F280 cmp si, 7
            if (m.sf == m.of) continue :sw 0xF289; // F283 jge 0xf289
            continue :sw 0xF285; // falls through
        },
        0xF285 => {
            m.mark(0xF285);
            m.wb(m.bp +% 0xFFEE, 0x1); // F285 mov byte ptr [bp - 0x12], 1
            continue :sw 0xF289; // falls through
        },
        0xF289 => {
            m.mark(0xF289);
            m.setAl(m.rb(m.di +% 0x9EEA)); // F289 mov al, byte ptr [di - 0x6116]
            m.cbw(); // F28D cbw
            m.si = m.ax; // F28E mov si, ax
            m.cmp(u16, m.si, 0x8); // F290 cmp si, 8
            if (m.zf or m.sf != m.of) continue :sw 0xF2B0; // F293 jle 0xf2b0
            m.cmp(u16, m.si, 0xD); // F295 cmp si, 0xd
            if (m.sf == m.of) continue :sw 0xF301; // F298 jge 0xf301
            m.setAl(m.rb(m.si +% 0x128C)); // F29A mov al, byte ptr [si + 0x128c]
            m.cbw(); // F29E cbw
            m.push(m.ax); // F29F push ax
            m.ax = m.di +% 0xFFF4; // F2A0 lea ax, [di - 0xc]
            m.push(m.ax); // F2A3 push ax
            m.far(.att_4cec, 0xF2A4); // F2A4 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F2A9 or ax, ax
            if (m.sf == m.of) continue :sw 0xF301; // F2AB jge 0xf301
            continue :sw 0xF12E; // F2AD jmp 0xf12e
        },
        0xF2B0 => {
            m.mark(0xF2B0);
            m.cmp(u16, m.si, 0x8); // F2B0 cmp si, 8
            if (!m.zf) continue :sw 0xF2DC; // F2B3 jne 0xf2dc
            m.push(0x6); // F2B5 push 6
            m.ax = m.di +% 0xFFF4; // F2B7 lea ax, [di - 0xc]
            m.push(m.ax); // F2BA push ax
            m.far(.att_4cec, 0xF2BB); // F2BB lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F2C0 or ax, ax
            if (m.sf == m.of) continue :sw 0xF301; // F2C2 jge 0xf301
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // F2C4 add word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // F2C8 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F2CB cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xF301; // F2CE jge 0xf301
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // F2D0 add word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // F2D5 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // F2D8 inc byte ptr [bx]
            continue :sw 0xF301; // F2DA jmp 0xf301
        },
        0xF2DC => {
            m.mark(0xF2DC);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // F2DC cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xF301; // F2E0 jne 0xf301
            m.cmp(u16, m.si, 0x1); // F2E2 cmp si, 1
            if (!m.zf and m.sf == m.of) continue :sw 0xF2F8; // F2E5 jg 0xf2f8
            m.push(0x9); // F2E7 push 9
            m.ax = m.di +% 0xFFF4; // F2E9 lea ax, [di - 0xc]
            m.push(m.ax); // F2EC push ax
            m.far(.att_4cec, 0xF2ED); // F2ED lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F2F2 or ax, ax
            if (m.sf != m.of) continue :sw 0xF301; // F2F4 jl 0xf301
            continue :sw 0xF2FD; // F2F6 jmp 0xf2fd
        },
        0xF2F8 => {
            m.mark(0xF2F8);
            m.cmp(u16, m.si, 0x7); // F2F8 cmp si, 7
            if (m.sf == m.of) continue :sw 0xF301; // F2FB jge 0xf301
            continue :sw 0xF2FD; // falls through
        },
        0xF2FD => {
            m.mark(0xF2FD);
            m.wb(m.bp +% 0xFFEE, 0x1); // F2FD mov byte ptr [bp - 0x12], 1
            continue :sw 0xF301; // falls through
        },
        0xF301 => {
            m.mark(0xF301);
            m.setAl(m.rb(m.di +% 0x9EE3)); // F301 mov al, byte ptr [di - 0x611d]
            m.cbw(); // F305 cbw
            m.si = m.ax; // F306 mov si, ax
            m.cmp(u16, m.si, 0x8); // F308 cmp si, 8
            if (m.zf or m.sf != m.of) continue :sw 0xF328; // F30B jle 0xf328
            m.cmp(u16, m.si, 0xD); // F30D cmp si, 0xd
            if (m.sf == m.of) continue :sw 0xF379; // F310 jge 0xf379
            m.setAl(m.rb(m.si +% 0x128C)); // F312 mov al, byte ptr [si + 0x128c]
            m.cbw(); // F316 cbw
            m.push(m.ax); // F317 push ax
            m.ax = m.di +% 0xFFED; // F318 lea ax, [di - 0x13]
            m.push(m.ax); // F31B push ax
            m.far(.att_4cec, 0xF31C); // F31C lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F321 or ax, ax
            if (m.sf == m.of) continue :sw 0xF379; // F323 jge 0xf379
            continue :sw 0xF12E; // F325 jmp 0xf12e
        },
        0xF328 => {
            m.mark(0xF328);
            m.cmp(u16, m.si, 0x8); // F328 cmp si, 8
            if (!m.zf) continue :sw 0xF354; // F32B jne 0xf354
            m.push(0x6); // F32D push 6
            m.ax = m.di +% 0xFFED; // F32F lea ax, [di - 0x13]
            m.push(m.ax); // F332 push ax
            m.far(.att_4cec, 0xF333); // F333 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F338 or ax, ax
            if (m.sf == m.of) continue :sw 0xF379; // F33A jge 0xf379
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // F33C add word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // F340 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F343 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xF379; // F346 jge 0xf379
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // F348 add word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // F34D mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // F350 inc byte ptr [bx]
            continue :sw 0xF379; // F352 jmp 0xf379
        },
        0xF354 => {
            m.mark(0xF354);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // F354 cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xF379; // F358 jne 0xf379
            m.cmp(u16, m.si, 0x1); // F35A cmp si, 1
            if (!m.zf and m.sf == m.of) continue :sw 0xF370; // F35D jg 0xf370
            m.push(0x9); // F35F push 9
            m.ax = m.di +% 0xFFED; // F361 lea ax, [di - 0x13]
            m.push(m.ax); // F364 push ax
            m.far(.att_4cec, 0xF365); // F365 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F36A or ax, ax
            if (m.sf != m.of) continue :sw 0xF379; // F36C jl 0xf379
            continue :sw 0xF375; // F36E jmp 0xf375
        },
        0xF370 => {
            m.mark(0xF370);
            m.cmp(u16, m.si, 0x7); // F370 cmp si, 7
            if (m.sf == m.of) continue :sw 0xF379; // F373 jge 0xf379
            continue :sw 0xF375; // falls through
        },
        0xF375 => {
            m.mark(0xF375);
            m.wb(m.bp +% 0xFFEE, 0x1); // F375 mov byte ptr [bp - 0x12], 1
            continue :sw 0xF379; // falls through
        },
        0xF379 => {
            m.mark(0xF379);
            m.setAl(m.rb(m.di +% 0x9EE1)); // F379 mov al, byte ptr [di - 0x611f]
            m.cbw(); // F37D cbw
            m.si = m.ax; // F37E mov si, ax
            m.cmp(u16, m.si, 0x8); // F380 cmp si, 8
            if (m.zf or m.sf != m.of) continue :sw 0xF3A0; // F383 jle 0xf3a0
            m.cmp(u16, m.si, 0xD); // F385 cmp si, 0xd
            if (m.sf == m.of) continue :sw 0xF3F1; // F388 jge 0xf3f1
            m.setAl(m.rb(m.si +% 0x128C)); // F38A mov al, byte ptr [si + 0x128c]
            m.cbw(); // F38E cbw
            m.push(m.ax); // F38F push ax
            m.ax = m.di +% 0xFFEB; // F390 lea ax, [di - 0x15]
            m.push(m.ax); // F393 push ax
            m.far(.att_4cec, 0xF394); // F394 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F399 or ax, ax
            if (m.sf == m.of) continue :sw 0xF3F1; // F39B jge 0xf3f1
            continue :sw 0xF12E; // F39D jmp 0xf12e
        },
        0xF3A0 => {
            m.mark(0xF3A0);
            m.cmp(u16, m.si, 0x8); // F3A0 cmp si, 8
            if (!m.zf) continue :sw 0xF3CC; // F3A3 jne 0xf3cc
            m.push(0x6); // F3A5 push 6
            m.ax = m.di +% 0xFFEB; // F3A7 lea ax, [di - 0x15]
            m.push(m.ax); // F3AA push ax
            m.far(.att_4cec, 0xF3AB); // F3AB lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F3B0 or ax, ax
            if (m.sf == m.of) continue :sw 0xF3F1; // F3B2 jge 0xf3f1
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // F3B4 add word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // F3B8 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F3BB cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xF3F1; // F3BE jge 0xf3f1
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // F3C0 add word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // F3C5 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // F3C8 inc byte ptr [bx]
            continue :sw 0xF3F1; // F3CA jmp 0xf3f1
        },
        0xF3CC => {
            m.mark(0xF3CC);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // F3CC cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xF3F1; // F3D0 jne 0xf3f1
            m.cmp(u16, m.si, 0x1); // F3D2 cmp si, 1
            if (!m.zf and m.sf == m.of) continue :sw 0xF3E8; // F3D5 jg 0xf3e8
            m.push(0x9); // F3D7 push 9
            m.ax = m.di +% 0xFFEB; // F3D9 lea ax, [di - 0x15]
            m.push(m.ax); // F3DC push ax
            m.far(.att_4cec, 0xF3DD); // F3DD lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F3E2 or ax, ax
            if (m.sf != m.of) continue :sw 0xF3F1; // F3E4 jl 0xf3f1
            continue :sw 0xF3ED; // F3E6 jmp 0xf3ed
        },
        0xF3E8 => {
            m.mark(0xF3E8);
            m.cmp(u16, m.si, 0x7); // F3E8 cmp si, 7
            if (m.sf == m.of) continue :sw 0xF3F1; // F3EB jge 0xf3f1
            continue :sw 0xF3ED; // falls through
        },
        0xF3ED => {
            m.mark(0xF3ED);
            m.wb(m.bp +% 0xFFEE, 0x1); // F3ED mov byte ptr [bp - 0x12], 1
            continue :sw 0xF3F1; // falls through
        },
        0xF3F1 => {
            m.mark(0xF3F1);
            m.cmp(u16, m.di, 0x47); // F3F1 cmp di, 0x47
            if (m.sf != m.of) continue :sw 0xF400; // F3F4 jl 0xf400
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // F3F6 cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xF400; // F3FA jne 0xf400
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x24)); // F3FC add word ptr [bp - 2], 0x24
            continue :sw 0xF400; // falls through
        },
        0xF400 => {
            m.mark(0xF400);
            m.setAl(m.rb(m.di +% 0x9F09)); // F400 mov al, byte ptr [di - 0x60f7]
            m.cbw(); // F404 cbw
            m.si = m.ax; // F405 mov si, ax
            m.cmp(u16, m.si, 0x8); // F407 cmp si, 8
            if (m.zf or m.sf != m.of) continue :sw 0xF428; // F40A jle 0xf428
            m.cmp(u16, m.si, 0xD); // F40C cmp si, 0xd
            if (m.sf == m.of) continue :sw 0xF479; // F40F jge 0xf479
            m.setAl(m.rb(m.si +% 0x128C)); // F411 mov al, byte ptr [si + 0x128c]
            m.cbw(); // F415 cbw
            m.push(m.ax); // F416 push ax
            m.ax = m.di +% 0x0013; // F417 lea ax, [di + 0x13]
            m.push(m.ax); // F41A push ax
            m.far(.att_4cec, 0xF41B); // F41B lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F420 or ax, ax
            if (m.sf == m.of) continue :sw 0xF479; // F422 jge 0xf479
            continue :sw 0xF12E; // F424 jmp 0xf12e
        },
        0xF428 => {
            m.mark(0xF428);
            m.cmp(u16, m.si, 0x8); // F428 cmp si, 8
            if (!m.zf) continue :sw 0xF454; // F42B jne 0xf454
            m.push(0x6); // F42D push 6
            m.ax = m.di +% 0x0013; // F42F lea ax, [di + 0x13]
            m.push(m.ax); // F432 push ax
            m.far(.att_4cec, 0xF433); // F433 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F438 or ax, ax
            if (m.sf == m.of) continue :sw 0xF479; // F43A jge 0xf479
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // F43C add word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // F440 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F443 cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xF479; // F446 jge 0xf479
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // F448 add word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // F44D mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // F450 inc byte ptr [bx]
            continue :sw 0xF479; // F452 jmp 0xf479
        },
        0xF454 => {
            m.mark(0xF454);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // F454 cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xF479; // F458 jne 0xf479
            m.cmp(u16, m.si, 0x1); // F45A cmp si, 1
            if (!m.zf and m.sf == m.of) continue :sw 0xF470; // F45D jg 0xf470
            m.push(0x9); // F45F push 9
            m.ax = m.di +% 0x0013; // F461 lea ax, [di + 0x13]
            m.push(m.ax); // F464 push ax
            m.far(.att_4cec, 0xF465); // F465 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F46A or ax, ax
            if (m.sf != m.of) continue :sw 0xF479; // F46C jl 0xf479
            continue :sw 0xF475; // F46E jmp 0xf475
        },
        0xF470 => {
            m.mark(0xF470);
            m.cmp(u16, m.si, 0x7); // F470 cmp si, 7
            if (m.sf == m.of) continue :sw 0xF479; // F473 jge 0xf479
            continue :sw 0xF475; // falls through
        },
        0xF475 => {
            m.mark(0xF475);
            m.wb(m.bp +% 0xFFEE, 0x1); // F475 mov byte ptr [bp - 0x12], 1
            continue :sw 0xF479; // falls through
        },
        0xF479 => {
            m.mark(0xF479);
            m.setAl(m.rb(m.di +% 0x9F0B)); // F479 mov al, byte ptr [di - 0x60f5]
            m.cbw(); // F47D cbw
            m.si = m.ax; // F47E mov si, ax
            m.cmp(u16, m.si, 0x8); // F480 cmp si, 8
            if (m.zf or m.sf != m.of) continue :sw 0xF4A0; // F483 jle 0xf4a0
            m.cmp(u16, m.si, 0xD); // F485 cmp si, 0xd
            if (m.sf == m.of) continue :sw 0xF4F1; // F488 jge 0xf4f1
            m.setAl(m.rb(m.si +% 0x128C)); // F48A mov al, byte ptr [si + 0x128c]
            m.cbw(); // F48E cbw
            m.push(m.ax); // F48F push ax
            m.ax = m.di +% 0x0015; // F490 lea ax, [di + 0x15]
            m.push(m.ax); // F493 push ax
            m.far(.att_4cec, 0xF494); // F494 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F499 or ax, ax
            if (m.sf == m.of) continue :sw 0xF4F1; // F49B jge 0xf4f1
            continue :sw 0xF12E; // F49D jmp 0xf12e
        },
        0xF4A0 => {
            m.mark(0xF4A0);
            m.cmp(u16, m.si, 0x8); // F4A0 cmp si, 8
            if (!m.zf) continue :sw 0xF4CC; // F4A3 jne 0xf4cc
            m.push(0x6); // F4A5 push 6
            m.ax = m.di +% 0x0015; // F4A7 lea ax, [di + 0x15]
            m.push(m.ax); // F4AA push ax
            m.far(.att_4cec, 0xF4AB); // F4AB lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F4B0 or ax, ax
            if (m.sf == m.of) continue :sw 0xF4F1; // F4B2 jge 0xf4f1
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x64)); // F4B4 add word ptr [bp - 4], 0x64
            m.ax = m.rw(0x9356); // F4B8 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F4BB cmp word ptr [bp + 6], ax
            if (m.sf == m.of) continue :sw 0xF4F1; // F4BE jge 0xf4f1
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0xC8)); // F4C0 add word ptr [bp - 2], 0xc8
            m.bx = m.rw(m.bp +% 0x000A); // F4C5 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // F4C8 inc byte ptr [bx]
            continue :sw 0xF4F1; // F4CA jmp 0xf4f1
        },
        0xF4CC => {
            m.mark(0xF4CC);
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // F4CC cmp byte ptr [bp - 0x12], 0
            if (!m.zf) continue :sw 0xF4F1; // F4D0 jne 0xf4f1
            m.cmp(u16, m.si, 0x1); // F4D2 cmp si, 1
            if (!m.zf and m.sf == m.of) continue :sw 0xF4E8; // F4D5 jg 0xf4e8
            m.push(0x9); // F4D7 push 9
            m.ax = m.di +% 0x0015; // F4D9 lea ax, [di + 0x15]
            m.push(m.ax); // F4DC push ax
            m.far(.att_4cec, 0xF4DD); // F4DD lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F4E2 or ax, ax
            if (m.sf != m.of) continue :sw 0xF4F1; // F4E4 jl 0xf4f1
            continue :sw 0xF4ED; // F4E6 jmp 0xf4ed
        },
        0xF4E8 => {
            m.mark(0xF4E8);
            m.cmp(u16, m.si, 0x7); // F4E8 cmp si, 7
            if (m.sf == m.of) continue :sw 0xF4F1; // F4EB jge 0xf4f1
            continue :sw 0xF4ED; // falls through
        },
        0xF4ED => {
            m.mark(0xF4ED);
            m.wb(m.bp +% 0xFFEE, 0x1); // F4ED mov byte ptr [bp - 0x12], 1
            continue :sw 0xF4F1; // falls through
        },
        0xF4F1 => {
            m.mark(0xF4F1);
            m.ax = m.di; // F4F1 mov ax, di
            m.wb(0xA04B, m.al()); // F4F3 mov byte ptr [0xa04b], al
            m.wb(m.di +% 0x9EF6, 0x9); // F4F6 mov byte ptr [di - 0x610a], 9
            m.cmp(u8, m.rb(m.bp +% 0xFFEE), 0x0); // F4FB cmp byte ptr [bp - 0x12], 0
            if (m.zf) continue :sw 0xF504; // F4FF je 0xf504
            continue :sw 0xF13B; // F501 jmp 0xf13b
        },
        0xF504 => {
            m.mark(0xF504);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x15E)); // F504 add word ptr [bp - 4], 0x15e
            m.ax = m.rw(0x9356); // F509 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F50C cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xF514; // F50F jl 0xf514
            continue :sw 0xF13B; // F511 jmp 0xf13b
        },
        0xF514 => {
            m.mark(0xF514);
            continue :sw 0xF043; // F514 jmp 0xf043
        },
        0xF518 => {
            m.mark(0xF518);
            m.cmp(u8, m.rb(m.di +% 0xA164), 0xC); // F518 cmp byte ptr [di - 0x5e9c], 0xc
            if (!m.zf and m.sf == m.of) continue :sw 0xF522; // F51D jg 0xf522
            continue :sw 0xF5C0; // F51F jmp 0xf5c0
        },
        0xF522 => {
            m.mark(0xF522);
            m.setAl(m.rb(m.di +% 0xA164)); // F522 mov al, byte ptr [di - 0x5e9c]
            m.cbw(); // F526 cbw
            m.bx = m.ax; // F527 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // F529 mov al, byte ptr [bx + 0x490]
            m.cbw(); // F52D cbw
            m.si = m.ax; // F52E mov si, ax
            continue :sw 0xF530; // falls through
        },
        0xF530 => {
            m.mark(0xF530);
            m.di = m.add(u16, m.di, m.si); // F530 add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // F532 cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xF530; // F537 je 0xf530
            m.si = m.di; // F539 mov si, di
            m.setAl(m.rb(0xA04C)); // F53B mov al, byte ptr [0xa04c]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // F53E sub ah, ah
            m.di = m.ax; // F540 mov di, ax
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x5); // F542 cmp byte ptr [si - 0x610a], 5
            if (!m.zf and m.sf == m.of) continue :sw 0xF5C0; // F547 jg 0xf5c0
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x4); // F549 cmp byte ptr [si - 0x610a], 4
            if (m.sf != m.of) continue :sw 0xF5C0; // F54E jl 0xf5c0
            m.bx = m.di; // F550 mov bx, di
            m.cmp(u8, m.rb(m.bx +% 0xA51C), m.ah()); // F552 cmp byte ptr [bx - 0x5ae4], ah
            if (m.zf) continue :sw 0xF57A; // F556 je 0xf57a
            continue :sw 0xF558; // falls through
        },
        0xF558 => {
            m.mark(0xF558);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x32)); // F558 add word ptr [bp - 2], 0x32
            continue :sw 0xF55C; // falls through
        },
        0xF55C => {
            m.mark(0xF55C);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x1C2)); // F55C add word ptr [bp - 4], 0x1c2
            m.ax = m.rw(0x9356); // F561 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F564 cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xF56C; // F567 jl 0xf56c
            continue :sw 0xFA56; // F569 jmp 0xfa56
        },
        0xF56C => {
            m.mark(0xF56C);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x320)); // F56C add word ptr [bp - 2], 0x320
            continue :sw 0xF571; // falls through
        },
        0xF571 => {
            m.mark(0xF571);
            m.bx = m.rw(m.bp +% 0x000A); // F571 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // F574 inc byte ptr [bx]
            continue :sw 0xF9E2; // F576 jmp 0xf9e2
        },
        0xF57A => {
            m.mark(0xF57A);
            m.push(0x12); // F57A push 0x12
            m.push(m.di); // F57C push di
            m.far(.att_4cec, 0xF57D); // F57D lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F582 or ax, ax
            if (m.sf != m.of) continue :sw 0xF589; // F584 jl 0xf589
            continue :sw 0xF788; // F586 jmp 0xf788
        },
        0xF589 => {
            m.mark(0xF589);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // F589 inc word ptr [bp - 8]
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // F58C cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xF596; // F591 je 0xf596
            continue :sw 0xF788; // F593 jmp 0xf788
        },
        0xF596 => {
            m.mark(0xF596);
            m.cmp(u8, m.rb(0x931B), 0x1); // F596 cmp byte ptr [0x931b], 1
            if (m.zf or m.sf != m.of) continue :sw 0xF5A2; // F59B jle 0xf5a2
            m.ax = 0x80; // F59D mov ax, 0x80
            continue :sw 0xF5A5; // F5A0 jmp 0xf5a5
        },
        0xF5A2 => {
            m.mark(0xF5A2);
            m.ax = 0x148; // F5A2 mov ax, 0x148
            continue :sw 0xF5A5; // falls through
        },
        0xF5A5 => {
            m.mark(0xF5A5);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), m.ax)); // F5A5 add word ptr [bp - 4], ax
            m.ax = m.rw(0x9356); // F5A8 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F5AB cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xF5B3; // F5AE jl 0xf5b3
            continue :sw 0xF788; // F5B0 jmp 0xf788
        },
        0xF5B3 => {
            m.mark(0xF5B3);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x226)); // F5B3 add word ptr [bp - 2], 0x226
            m.bx = m.rw(m.bp +% 0x000A); // F5B8 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // F5BB inc byte ptr [bx]
            continue :sw 0xF788; // F5BD jmp 0xf788
        },
        0xF5C0 => {
            m.mark(0xF5C0);
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // F5C0 cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xF5E8; // F5C5 je 0xf5e8
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // F5C7 inc word ptr [bp - 6]
            m.ax = m.rw(0xA272); // F5CA mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F5CD cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xF5D5; // F5D0 jle 0xf5d5
            continue :sw 0xF67E; // F5D2 jmp 0xf67e
        },
        0xF5D5 => {
            m.mark(0xF5D5);
            m.setAl(m.rb(m.di +% 0x100A)); // F5D5 mov al, byte ptr [di + 0x100a]
            m.cbw(); // F5D9 cbw
            m.bx = m.ax; // F5DA mov bx, ax
            m.cmp(u8, m.rb(m.bx +% 0xA8C8), 0x0); // F5DC cmp byte ptr [bx - 0x5738], 0
            if (m.zf) continue :sw 0xF5E6; // F5E1 je 0xf5e6
            continue :sw 0xF67E; // F5E3 jmp 0xf67e
        },
        0xF5E6 => {
            m.mark(0xF5E6);
            continue :sw 0xF5B3; // F5E6 jmp 0xf5b3
        },
        0xF5E8 => {
            m.mark(0xF5E8);
            m.si = m.di +% 0x00B0; // F5E8 lea si, [di + 0xb0]
            m.bx = m.si; // F5EC mov bx, si
            m.setAl(m.rb(0xA03B)); // F5EE mov al, byte ptr [0xa03b]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // F5F1 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // F5F3 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x09B8)); // F5F5 mov al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // F5F9 mov bx, si
            m.setCl(m.rb(0xA03A)); // F5FB mov cl, byte ptr [0xa03a]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // F5FF sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // F601 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // F603 or al, byte ptr [bx + 0x9b8]
            if (m.zf) continue :sw 0xF616; // F607 je 0xf616
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x18)); // F609 add word ptr [bp - 2], 0x18
            m.cmp(u8, m.rb(m.di +% 0x37DA), m.ah()); // F60D cmp byte ptr [di + 0x37da], ah
            if (m.zf) continue :sw 0xF661; // F611 je 0xf661
            continue :sw 0xF788; // F613 jmp 0xf788
        },
        0xF616 => {
            m.mark(0xF616);
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // F616 cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xF620; // F61B je 0xf620
            continue :sw 0xF788; // F61D jmp 0xf788
        },
        0xF620 => {
            m.mark(0xF620);
            m.bx = m.si; // F620 mov bx, si
            m.setAl(m.rb(0xA03E)); // F622 mov al, byte ptr [0xa03e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // F625 sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // F627 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0BB4)); // F629 mov al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // F62D mov bx, si
            m.setCl(m.rb(0xA03F)); // F62F mov cl, byte ptr [0xa03f]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // F633 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // F635 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // F637 or al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // F63B mov bx, si
            m.setCl(m.rb(0xA03D)); // F63D mov cl, byte ptr [0xa03d]
            m.bx = m.sub(u16, m.bx, m.cx); // F641 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // F643 or al, byte ptr [bx + 0xab6]
            m.bx = m.di; // F647 mov bx, di
            m.setCl(m.rb(0xA041)); // F649 mov cl, byte ptr [0xa041]
            m.bx = m.sub(u16, m.bx, m.cx); // F64D sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0CFF))); // F64F or al, byte ptr [bx + 0xcff]
            m.bx = m.si; // F653 mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // F655 sub bx, word ptr [bp - 0xc]
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // F658 or al, byte ptr [bx + 0xbb4]
            if (!m.zf) continue :sw 0xF661; // F65C jne 0xf661
            continue :sw 0xF788; // F65E jmp 0xf788
        },
        0xF661 => {
            m.mark(0xF661);
            m.push(0x12); // F661 push 0x12
            m.push(m.di); // F663 push di
            m.far(.att_4cec, 0xF664); // F664 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F669 or ax, ax
            if (m.sf != m.of) continue :sw 0xF670; // F66B jl 0xf670
            continue :sw 0xF788; // F66D jmp 0xf788
        },
        0xF670 => {
            m.mark(0xF670);
            m.ax = m.rw(0xA272); // F670 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F673 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xF67B; // F676 jg 0xf67b
            continue :sw 0xF5B3; // F678 jmp 0xf5b3
        },
        0xF67B => {
            m.mark(0xF67B);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // F67B inc word ptr [bp - 8]
            continue :sw 0xF67E; // falls through
        },
        0xF67E => {
            m.mark(0xF67E);
            m.wb(m.di +% 0x9EF6, 0x0); // F67E mov byte ptr [di - 0x610a], 0
            m.si = m.di +% 0x0009; // F683 lea si, [di + 9]
            continue :sw 0xF69A; // F686 jmp 0xf69a
        },
        0xF688 => {
            m.mark(0xF688);
            m.push(0x9); // F688 push 9
            m.push(m.si); // F68A push si
            m.far(.att_4cec, 0xF68B); // F68B lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F690 or ax, ax
            if (m.sf != m.of) continue :sw 0xF697; // F692 jl 0xf697
            continue :sw 0xF783; // F694 jmp 0xf783
        },
        0xF697 => {
            m.mark(0xF697);
            m.si = m.add(u16, m.si, 0x9); // F697 add si, 9
            continue :sw 0xF69A; // falls through
        },
        0xF69A => {
            m.mark(0xF69A);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // F69A cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xF688; // F69F je 0xf688
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // F6A1 cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xF6C1; // F6A6 jge 0xf6c1
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x1); // F6A8 cmp byte ptr [si - 0x610a], 1
            if (m.zf or m.sf != m.of) continue :sw 0xF6B2; // F6AD jle 0xf6b2
            continue :sw 0xF783; // F6AF jmp 0xf783
        },
        0xF6B2 => {
            m.mark(0xF6B2);
            m.push(0x9); // F6B2 push 9
            m.push(m.si); // F6B4 push si
            m.far(.att_4cec, 0xF6B5); // F6B5 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F6BA or ax, ax
            if (m.sf != m.of) continue :sw 0xF6C1; // F6BC jl 0xf6c1
            continue :sw 0xF783; // F6BE jmp 0xf783
        },
        0xF6C1 => {
            m.mark(0xF6C1);
            m.si = m.di +% 0x000B; // F6C1 lea si, [di + 0xb]
            continue :sw 0xF6D8; // F6C4 jmp 0xf6d8
        },
        0xF6C6 => {
            m.mark(0xF6C6);
            m.push(0x9); // F6C6 push 9
            m.push(m.si); // F6C8 push si
            m.far(.att_4cec, 0xF6C9); // F6C9 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F6CE or ax, ax
            if (m.sf != m.of) continue :sw 0xF6D5; // F6D0 jl 0xf6d5
            continue :sw 0xF783; // F6D2 jmp 0xf783
        },
        0xF6D5 => {
            m.mark(0xF6D5);
            m.si = m.add(u16, m.si, 0xB); // F6D5 add si, 0xb
            continue :sw 0xF6D8; // falls through
        },
        0xF6D8 => {
            m.mark(0xF6D8);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // F6D8 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xF6C6; // F6DD je 0xf6c6
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // F6DF cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xF6FF; // F6E4 jge 0xf6ff
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x1); // F6E6 cmp byte ptr [si - 0x610a], 1
            if (m.zf or m.sf != m.of) continue :sw 0xF6F0; // F6EB jle 0xf6f0
            continue :sw 0xF783; // F6ED jmp 0xf783
        },
        0xF6F0 => {
            m.mark(0xF6F0);
            m.push(0x9); // F6F0 push 9
            m.push(m.si); // F6F2 push si
            m.far(.att_4cec, 0xF6F3); // F6F3 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F6F8 or ax, ax
            if (m.sf != m.of) continue :sw 0xF6FF; // F6FA jl 0xf6ff
            continue :sw 0xF783; // F6FC jmp 0xf783
        },
        0xF6FF => {
            m.mark(0xF6FF);
            m.si = m.di +% 0xFFF7; // F6FF lea si, [di - 9]
            continue :sw 0xF715; // F702 jmp 0xf715
        },
        0xF706 => {
            m.mark(0xF706);
            m.push(0x9); // F706 push 9
            m.push(m.si); // F708 push si
            m.far(.att_4cec, 0xF709); // F709 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F70E or ax, ax
            if (m.sf == m.of) continue :sw 0xF783; // F710 jge 0xf783
            m.si = m.sub(u16, m.si, 0x9); // F712 sub si, 9
            continue :sw 0xF715; // falls through
        },
        0xF715 => {
            m.mark(0xF715);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // F715 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xF706; // F71A je 0xf706
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // F71C cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xF736; // F721 jge 0xf736
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x1); // F723 cmp byte ptr [si - 0x610a], 1
            if (!m.zf and m.sf == m.of) continue :sw 0xF783; // F728 jg 0xf783
            m.push(0x9); // F72A push 9
            m.push(m.si); // F72C push si
            m.far(.att_4cec, 0xF72D); // F72D lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F732 or ax, ax
            if (m.sf == m.of) continue :sw 0xF783; // F734 jge 0xf783
            continue :sw 0xF736; // falls through
        },
        0xF736 => {
            m.mark(0xF736);
            m.si = m.di +% 0xFFF5; // F736 lea si, [di - 0xb]
            continue :sw 0xF74B; // F739 jmp 0xf74b
        },
        0xF73C => {
            m.mark(0xF73C);
            m.push(0x9); // F73C push 9
            m.push(m.si); // F73E push si
            m.far(.att_4cec, 0xF73F); // F73F lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F744 or ax, ax
            if (m.sf == m.of) continue :sw 0xF783; // F746 jge 0xf783
            m.si = m.sub(u16, m.si, 0xB); // F748 sub si, 0xb
            continue :sw 0xF74B; // falls through
        },
        0xF74B => {
            m.mark(0xF74B);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // F74B cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xF73C; // F750 je 0xf73c
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // F752 cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xF76C; // F757 jge 0xf76c
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x1); // F759 cmp byte ptr [si - 0x610a], 1
            if (!m.zf and m.sf == m.of) continue :sw 0xF783; // F75E jg 0xf783
            m.push(0x9); // F760 push 9
            m.push(m.si); // F762 push si
            m.far(.att_4cec, 0xF763); // F763 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F768 or ax, ax
            if (m.sf == m.of) continue :sw 0xF783; // F76A jge 0xf783
            continue :sw 0xF76C; // falls through
        },
        0xF76C => {
            m.mark(0xF76C);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x190)); // F76C add word ptr [bp - 4], 0x190
            m.ax = m.rw(0x9356); // F771 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F774 cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xF783; // F777 jg 0xf783
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x226)); // F779 add word ptr [bp - 2], 0x226
            m.bx = m.rw(m.bp +% 0x000A); // F77E mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // F781 inc byte ptr [bx]
            continue :sw 0xF783; // falls through
        },
        0xF783 => {
            m.mark(0xF783);
            m.wb(m.di +% 0x9EF6, 0xA); // F783 mov byte ptr [di - 0x610a], 0xa
            continue :sw 0xF788; // falls through
        },
        0xF788 => {
            m.mark(0xF788);
            m.setAl(m.rb(0xA04D)); // F788 mov al, byte ptr [0xa04d]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // F78B sub ah, ah
            m.di = m.ax; // F78D mov di, ax
            m.cmp(u16, m.di, 0x62); // F78F cmp di, 0x62
            if (m.zf or m.sf != m.of) continue :sw 0xF797; // F792 jle 0xf797
            continue :sw 0xF9E2; // F794 jmp 0xf9e2
        },
        0xF797 => {
            m.mark(0xF797);
            m.cmp(u8, m.rb(m.di +% 0xA164), 0xC); // F797 cmp byte ptr [di - 0x5e9c], 0xc
            if (m.zf or m.sf != m.of) continue :sw 0xF81A; // F79C jle 0xf81a
            m.setAl(m.rb(m.di +% 0xA164)); // F79E mov al, byte ptr [di - 0x5e9c]
            m.cbw(); // F7A2 cbw
            m.bx = m.ax; // F7A3 mov bx, ax
            m.setAl(m.rb(m.bx +% 0x0490)); // F7A5 mov al, byte ptr [bx + 0x490]
            m.cbw(); // F7A9 cbw
            m.si = m.ax; // F7AA mov si, ax
            continue :sw 0xF7AC; // falls through
        },
        0xF7AC => {
            m.mark(0xF7AC);
            m.di = m.add(u16, m.di, m.si); // F7AC add di, si
            m.cmp(u8, m.rb(m.di +% 0x9EF6), 0x0); // F7AE cmp byte ptr [di - 0x610a], 0
            if (m.zf) continue :sw 0xF7AC; // F7B3 je 0xf7ac
            m.si = m.di; // F7B5 mov si, di
            m.setAl(m.rb(0xA04D)); // F7B7 mov al, byte ptr [0xa04d]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // F7BA sub ah, ah
            m.di = m.ax; // F7BC mov di, ax
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x5); // F7BE cmp byte ptr [si - 0x610a], 5
            if (!m.zf and m.sf == m.of) continue :sw 0xF81A; // F7C3 jg 0xf81a
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x4); // F7C5 cmp byte ptr [si - 0x610a], 4
            if (m.sf != m.of) continue :sw 0xF81A; // F7CA jl 0xf81a
            m.bx = m.di; // F7CC mov bx, di
            m.cmp(u8, m.rb(m.bx +% 0xA51C), m.ah()); // F7CE cmp byte ptr [bx - 0x5ae4], ah
            if (m.zf) continue :sw 0xF7D7; // F7D2 je 0xf7d7
            continue :sw 0xF558; // F7D4 jmp 0xf558
        },
        0xF7D7 => {
            m.mark(0xF7D7);
            m.push(0x12); // F7D7 push 0x12
            m.push(m.di); // F7D9 push di
            m.far(.att_4cec, 0xF7DA); // F7DA lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F7DF or ax, ax
            if (m.sf != m.of) continue :sw 0xF7E6; // F7E1 jl 0xf7e6
            continue :sw 0xF9E2; // F7E3 jmp 0xf9e2
        },
        0xF7E6 => {
            m.mark(0xF7E6);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // F7E6 inc word ptr [bp - 8]
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // F7E9 cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xF7F3; // F7EE je 0xf7f3
            continue :sw 0xF9E2; // F7F0 jmp 0xf9e2
        },
        0xF7F3 => {
            m.mark(0xF7F3);
            m.cmp(u8, m.rb(0x931B), 0x1); // F7F3 cmp byte ptr [0x931b], 1
            if (m.zf or m.sf != m.of) continue :sw 0xF800; // F7F8 jle 0xf800
            m.ax = 0x80; // F7FA mov ax, 0x80
            continue :sw 0xF803; // F7FD jmp 0xf803
        },
        0xF800 => {
            m.mark(0xF800);
            m.ax = 0x148; // F800 mov ax, 0x148
            continue :sw 0xF803; // falls through
        },
        0xF803 => {
            m.mark(0xF803);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), m.ax)); // F803 add word ptr [bp - 4], ax
            m.ax = m.rw(0x9356); // F806 mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F809 cmp word ptr [bp + 6], ax
            if (m.sf != m.of) continue :sw 0xF811; // F80C jl 0xf811
            continue :sw 0xF9E2; // F80E jmp 0xf9e2
        },
        0xF811 => {
            m.mark(0xF811);
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x226)); // F811 add word ptr [bp - 2], 0x226
            continue :sw 0xF571; // F816 jmp 0xf571
        },
        0xF81A => {
            m.mark(0xF81A);
            m.cmp(u8, m.rb(m.di +% 0xA51C), 0x0); // F81A cmp byte ptr [di - 0x5ae4], 0
            if (m.zf) continue :sw 0xF842; // F81F je 0xf842
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // F821 inc word ptr [bp - 6]
            m.ax = m.rw(0xA272); // F824 mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F827 cmp word ptr [bp + 6], ax
            if (m.zf or m.sf != m.of) continue :sw 0xF82F; // F82A jle 0xf82f
            continue :sw 0xF8D8; // F82C jmp 0xf8d8
        },
        0xF82F => {
            m.mark(0xF82F);
            m.setAl(m.rb(m.di +% 0x100A)); // F82F mov al, byte ptr [di + 0x100a]
            m.cbw(); // F833 cbw
            m.bx = m.ax; // F834 mov bx, ax
            m.cmp(u8, m.rb(m.bx +% 0xA8C8), 0x0); // F836 cmp byte ptr [bx - 0x5738], 0
            if (m.zf) continue :sw 0xF840; // F83B je 0xf840
            continue :sw 0xF8D8; // F83D jmp 0xf8d8
        },
        0xF840 => {
            m.mark(0xF840);
            continue :sw 0xF811; // F840 jmp 0xf811
        },
        0xF842 => {
            m.mark(0xF842);
            m.si = m.di +% 0x00B0; // F842 lea si, [di + 0xb0]
            m.bx = m.si; // F846 mov bx, si
            m.setAl(m.rb(0xA03B)); // F848 mov al, byte ptr [0xa03b]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // F84B sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // F84D sub bx, ax
            m.setAl(m.rb(m.bx +% 0x09B8)); // F84F mov al, byte ptr [bx + 0x9b8]
            m.bx = m.si; // F853 mov bx, si
            m.setCl(m.rb(0xA03A)); // F855 mov cl, byte ptr [0xa03a]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // F859 sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // F85B sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x09B8))); // F85D or al, byte ptr [bx + 0x9b8]
            if (m.zf) continue :sw 0xF870; // F861 je 0xf870
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x18)); // F863 add word ptr [bp - 2], 0x18
            m.cmp(u8, m.rb(m.di +% 0x37DA), m.ah()); // F867 cmp byte ptr [di + 0x37da], ah
            if (m.zf) continue :sw 0xF8BB; // F86B je 0xf8bb
            continue :sw 0xF9E2; // F86D jmp 0xf9e2
        },
        0xF870 => {
            m.mark(0xF870);
            m.cmp(u8, m.rb(m.di +% 0x37DA), 0x0); // F870 cmp byte ptr [di + 0x37da], 0
            if (m.zf) continue :sw 0xF87A; // F875 je 0xf87a
            continue :sw 0xF9E2; // F877 jmp 0xf9e2
        },
        0xF87A => {
            m.mark(0xF87A);
            m.bx = m.si; // F87A mov bx, si
            m.setAl(m.rb(0xA03E)); // F87C mov al, byte ptr [0xa03e]
            m.setAh(m.sub(u8, m.ah(), m.ah())); // F87F sub ah, ah
            m.bx = m.sub(u16, m.bx, m.ax); // F881 sub bx, ax
            m.setAl(m.rb(m.bx +% 0x0BB4)); // F883 mov al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // F887 mov bx, si
            m.setCl(m.rb(0xA03F)); // F889 mov cl, byte ptr [0xa03f]
            m.setCh(m.sub(u8, m.ch(), m.ch())); // F88D sub ch, ch
            m.bx = m.sub(u16, m.bx, m.cx); // F88F sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // F891 or al, byte ptr [bx + 0xbb4]
            m.bx = m.si; // F895 mov bx, si
            m.setCl(m.rb(0xA03C)); // F897 mov cl, byte ptr [0xa03c]
            m.bx = m.sub(u16, m.bx, m.cx); // F89B sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0AB6))); // F89D or al, byte ptr [bx + 0xab6]
            m.bx = m.di; // F8A1 mov bx, di
            m.setCl(m.rb(0xA041)); // F8A3 mov cl, byte ptr [0xa041]
            m.bx = m.sub(u16, m.bx, m.cx); // F8A7 sub bx, cx
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0CFF))); // F8A9 or al, byte ptr [bx + 0xcff]
            m.bx = m.si; // F8AD mov bx, si
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0xFFF4)); // F8AF sub bx, word ptr [bp - 0xc]
            m.setAl(m.@"or"(u8, m.al(), m.rb(m.bx +% 0x0BB4))); // F8B2 or al, byte ptr [bx + 0xbb4]
            if (!m.zf) continue :sw 0xF8BB; // F8B6 jne 0xf8bb
            continue :sw 0xF9E2; // F8B8 jmp 0xf9e2
        },
        0xF8BB => {
            m.mark(0xF8BB);
            m.push(0x12); // F8BB push 0x12
            m.push(m.di); // F8BD push di
            m.far(.att_4cec, 0xF8BE); // F8BE lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F8C3 or ax, ax
            if (m.sf != m.of) continue :sw 0xF8CA; // F8C5 jl 0xf8ca
            continue :sw 0xF9E2; // F8C7 jmp 0xf9e2
        },
        0xF8CA => {
            m.mark(0xF8CA);
            m.ax = m.rw(0xA272); // F8CA mov ax, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F8CD cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xF8D5; // F8D0 jg 0xf8d5
            continue :sw 0xF811; // F8D2 jmp 0xf811
        },
        0xF8D5 => {
            m.mark(0xF8D5);
            m.ww(m.bp +% 0xFFF8, m.inc(u16, m.rw(m.bp +% 0xFFF8))); // F8D5 inc word ptr [bp - 8]
            continue :sw 0xF8D8; // falls through
        },
        0xF8D8 => {
            m.mark(0xF8D8);
            m.wb(m.di +% 0x9EF6, 0x0); // F8D8 mov byte ptr [di - 0x610a], 0
            m.si = m.di +% 0x0009; // F8DD lea si, [di + 9]
            continue :sw 0xF8F4; // F8E0 jmp 0xf8f4
        },
        0xF8E2 => {
            m.mark(0xF8E2);
            m.push(0x9); // F8E2 push 9
            m.push(m.si); // F8E4 push si
            m.far(.att_4cec, 0xF8E5); // F8E5 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F8EA or ax, ax
            if (m.sf != m.of) continue :sw 0xF8F1; // F8EC jl 0xf8f1
            continue :sw 0xF9DD; // F8EE jmp 0xf9dd
        },
        0xF8F1 => {
            m.mark(0xF8F1);
            m.si = m.add(u16, m.si, 0x9); // F8F1 add si, 9
            continue :sw 0xF8F4; // falls through
        },
        0xF8F4 => {
            m.mark(0xF8F4);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // F8F4 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xF8E2; // F8F9 je 0xf8e2
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // F8FB cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xF91B; // F900 jge 0xf91b
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x1); // F902 cmp byte ptr [si - 0x610a], 1
            if (m.zf or m.sf != m.of) continue :sw 0xF90C; // F907 jle 0xf90c
            continue :sw 0xF9DD; // F909 jmp 0xf9dd
        },
        0xF90C => {
            m.mark(0xF90C);
            m.push(0x9); // F90C push 9
            m.push(m.si); // F90E push si
            m.far(.att_4cec, 0xF90F); // F90F lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F914 or ax, ax
            if (m.sf != m.of) continue :sw 0xF91B; // F916 jl 0xf91b
            continue :sw 0xF9DD; // F918 jmp 0xf9dd
        },
        0xF91B => {
            m.mark(0xF91B);
            m.si = m.di +% 0x000B; // F91B lea si, [di + 0xb]
            continue :sw 0xF932; // F91E jmp 0xf932
        },
        0xF920 => {
            m.mark(0xF920);
            m.push(0x9); // F920 push 9
            m.push(m.si); // F922 push si
            m.far(.att_4cec, 0xF923); // F923 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F928 or ax, ax
            if (m.sf != m.of) continue :sw 0xF92F; // F92A jl 0xf92f
            continue :sw 0xF9DD; // F92C jmp 0xf9dd
        },
        0xF92F => {
            m.mark(0xF92F);
            m.si = m.add(u16, m.si, 0xB); // F92F add si, 0xb
            continue :sw 0xF932; // falls through
        },
        0xF932 => {
            m.mark(0xF932);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // F932 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xF920; // F937 je 0xf920
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // F939 cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xF959; // F93E jge 0xf959
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x1); // F940 cmp byte ptr [si - 0x610a], 1
            if (m.zf or m.sf != m.of) continue :sw 0xF94A; // F945 jle 0xf94a
            continue :sw 0xF9DD; // F947 jmp 0xf9dd
        },
        0xF94A => {
            m.mark(0xF94A);
            m.push(0x9); // F94A push 9
            m.push(m.si); // F94C push si
            m.far(.att_4cec, 0xF94D); // F94D lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F952 or ax, ax
            if (m.sf != m.of) continue :sw 0xF959; // F954 jl 0xf959
            continue :sw 0xF9DD; // F956 jmp 0xf9dd
        },
        0xF959 => {
            m.mark(0xF959);
            m.si = m.di +% 0xFFF7; // F959 lea si, [di - 9]
            continue :sw 0xF96F; // F95C jmp 0xf96f
        },
        0xF960 => {
            m.mark(0xF960);
            m.push(0x9); // F960 push 9
            m.push(m.si); // F962 push si
            m.far(.att_4cec, 0xF963); // F963 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F968 or ax, ax
            if (m.sf == m.of) continue :sw 0xF9DD; // F96A jge 0xf9dd
            m.si = m.sub(u16, m.si, 0x9); // F96C sub si, 9
            continue :sw 0xF96F; // falls through
        },
        0xF96F => {
            m.mark(0xF96F);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // F96F cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xF960; // F974 je 0xf960
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // F976 cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xF990; // F97B jge 0xf990
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x1); // F97D cmp byte ptr [si - 0x610a], 1
            if (!m.zf and m.sf == m.of) continue :sw 0xF9DD; // F982 jg 0xf9dd
            m.push(0x9); // F984 push 9
            m.push(m.si); // F986 push si
            m.far(.att_4cec, 0xF987); // F987 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F98C or ax, ax
            if (m.sf == m.of) continue :sw 0xF9DD; // F98E jge 0xf9dd
            continue :sw 0xF990; // falls through
        },
        0xF990 => {
            m.mark(0xF990);
            m.si = m.di +% 0xFFF5; // F990 lea si, [di - 0xb]
            continue :sw 0xF9A5; // F993 jmp 0xf9a5
        },
        0xF996 => {
            m.mark(0xF996);
            m.push(0x9); // F996 push 9
            m.push(m.si); // F998 push si
            m.far(.att_4cec, 0xF999); // F999 lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F99E or ax, ax
            if (m.sf == m.of) continue :sw 0xF9DD; // F9A0 jge 0xf9dd
            m.si = m.sub(u16, m.si, 0xB); // F9A2 sub si, 0xb
            continue :sw 0xF9A5; // falls through
        },
        0xF9A5 => {
            m.mark(0xF9A5);
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x0); // F9A5 cmp byte ptr [si - 0x610a], 0
            if (m.zf) continue :sw 0xF996; // F9AA je 0xf996
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x7); // F9AC cmp byte ptr [si - 0x610a], 7
            if (m.sf == m.of) continue :sw 0xF9C6; // F9B1 jge 0xf9c6
            m.cmp(u8, m.rb(m.si +% 0x9EF6), 0x1); // F9B3 cmp byte ptr [si - 0x610a], 1
            if (!m.zf and m.sf == m.of) continue :sw 0xF9DD; // F9B8 jg 0xf9dd
            m.push(0x9); // F9BA push 9
            m.push(m.si); // F9BC push si
            m.far(.att_4cec, 0xF9BD); // F9BD lcall 0x4793, 0x4cec
            m.ax = m.@"or"(u16, m.ax, m.ax); // F9C2 or ax, ax
            if (m.sf == m.of) continue :sw 0xF9DD; // F9C4 jge 0xf9dd
            continue :sw 0xF9C6; // falls through
        },
        0xF9C6 => {
            m.mark(0xF9C6);
            m.ww(m.bp +% 0xFFFC, m.add(u16, m.rw(m.bp +% 0xFFFC), 0x190)); // F9C6 add word ptr [bp - 4], 0x190
            m.ax = m.rw(0x9356); // F9CB mov ax, word ptr [0x9356]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.ax); // F9CE cmp word ptr [bp + 6], ax
            if (!m.zf and m.sf == m.of) continue :sw 0xF9DD; // F9D1 jg 0xf9dd
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), 0x226)); // F9D3 add word ptr [bp - 2], 0x226
            m.bx = m.rw(m.bp +% 0x000A); // F9D8 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // F9DB inc byte ptr [bx]
            continue :sw 0xF9DD; // falls through
        },
        0xF9DD => {
            m.mark(0xF9DD);
            m.wb(m.di +% 0x9EF6, 0xA); // F9DD mov byte ptr [di - 0x610a], 0xa
            continue :sw 0xF9E2; // falls through
        },
        0xF9E2 => {
            m.mark(0xF9E2);
            m.ax = m.rw(m.bp +% 0xFFF8); // F9E2 mov ax, word ptr [bp - 8]
            m.ww(m.bp +% 0xFFFA, m.add(u16, m.rw(m.bp +% 0xFFFA), m.ax)); // F9E5 add word ptr [bp - 6], ax
            if (m.zf) continue :sw 0xFA18; // F9E8 je 0xfa18
            m.cx = m.rw(0xA272); // F9EA mov cx, word ptr [0xa272]
            m.cmp(u16, m.rw(m.bp +% 0x0006), m.cx); // F9EE cmp word ptr [bp + 6], cx
            if (!m.zf and m.sf == m.of) continue :sw 0xFA18; // F9F1 jg 0xfa18
            m.cmp(u16, m.rw(m.bp +% 0xFFFA), 0x1); // F9F3 cmp word ptr [bp - 6], 1
            if (!m.zf and m.sf == m.of) continue :sw 0xFA05; // F9F7 jg 0xfa05
            m.ax = m.@"or"(u16, m.ax, m.ax); // F9F9 or ax, ax
            if (m.zf) continue :sw 0xFA18; // F9FB je 0xfa18
            m.cmp(u16, m.rw(0x378E), 0x1B58); // F9FD cmp word ptr [0x378e], 0x1b58
            if (!m.cf) continue :sw 0xFA18; // FA03 jae 0xfa18
            continue :sw 0xFA05; // falls through
        },
        0xFA05 => {
            m.mark(0xFA05);
            m.bx = m.rw(m.bp +% 0x000A); // FA05 mov bx, word ptr [bp + 0xa]
            m.wb(m.bx, m.inc(u8, m.rb(m.bx))); // FA08 inc byte ptr [bx]
            m.cmp(u16, m.rw(m.bp +% 0x0008), 0x1); // FA0A cmp word ptr [bp + 8], 1
            m.ax = m.sbb(u16, m.ax, m.ax); // FA0E sbb ax, ax
            m.setAl(m.@"and"(u8, m.al(), 0x38)); // FA10 and al, 0x38
            m.ax = m.add(u16, m.ax, 0x1F4); // FA12 add ax, 0x1f4
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), m.ax)); // FA15 add word ptr [bp - 2], ax
            continue :sw 0xFA18; // falls through
        },
        0xFA18 => {
            m.mark(0xFA18);
            m.bx = m.rw(m.bp +% 0x000A); // FA18 mov bx, word ptr [bp + 0xa]
            m.cmp(u8, m.rb(m.bx), 0x1); // FA1B cmp byte ptr [bx], 1
            if (!m.zf) continue :sw 0xFA26; // FA1E jne 0xfa26
            m.ax = m.rw(m.bp +% 0xFFFC); // FA20 mov ax, word ptr [bp - 4]
            m.ww(m.bp +% 0xFFFE, m.add(u16, m.rw(m.bp +% 0xFFFE), m.ax)); // FA23 add word ptr [bp - 2], ax
            continue :sw 0xFA26; // falls through
        },
        0xFA26 => {
            m.mark(0xFA26);
            m.@"test"(u8, m.rb(0xA5F5), 0x10); // FA26 test byte ptr [0xa5f5], 0x10
            if (m.zf) continue :sw 0xFA30; // FA2B je 0xfa30
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // FA2D inc word ptr [bp - 6]
            continue :sw 0xFA30; // falls through
        },
        0xFA30 => {
            m.mark(0xFA30);
            m.cmp(u16, m.rw(m.bp +% 0xFFFA), 0x0); // FA30 cmp word ptr [bp - 6], 0
            if (!m.zf) continue :sw 0xFA39; // FA34 jne 0xfa39
            continue :sw 0xDAEF; // FA36 jmp 0xdaef
        },
        0xFA39 => {
            m.mark(0xFA39);
            m.bx = m.rw(m.bp +% 0xFFFA); // FA39 mov bx, word ptr [bp - 6]
            m.bx = m.sub(u16, m.bx, m.rw(m.bp +% 0x0008)); // FA3C sub bx, word ptr [bp + 8]
            m.bx = m.shl(u16, m.bx, 0x1); // FA3F shl bx, 1
            m.ax = m.rw(m.bx +% 0x0388); // FA41 mov ax, word ptr [bx + 0x388]
            m.bx = m.rw(m.bp +% 0x0008); // FA45 mov bx, word ptr [bp + 8]
            m.bx = m.shl(u16, m.bx, 0x1); // FA48 shl bx, 1
            m.ax = m.add(u16, m.ax, m.rw(m.bx +% 0x03EA)); // FA4A add ax, word ptr [bx + 0x3ea]
            m.ax = m.add(u16, m.ax, m.rw(m.bp +% 0xFFFE)); // FA4E add ax, word ptr [bp - 2]
            m.si = m.pop(); // FA51 pop si
            m.di = m.pop(); // FA52 pop di
            m.sp = m.bp;
            m.bp = m.pop(); // FA53 leave
            return; // FA54 retf
        },
        0xFA56 => {
            m.mark(0xFA56);
            m.ww(m.bp +% 0xFFFA, m.inc(u16, m.rw(m.bp +% 0xFFFA))); // FA56 inc word ptr [bp - 6]
            continue :sw 0xF9E2; // FA59 jmp 0xf9e2
        },
        else => unreachable,
    }
}
