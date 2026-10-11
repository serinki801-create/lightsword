// language: C, file: pac_oracle.h, target: iOS 26.x arm64e, Theos
// Track A — PAC signing oracle (userspace, CVE-2026-20700 class).
//
// Signals: ключи ПРОЦЕССА (IA/IB userland). Ядровые указатели этими
// ключами не подписываются и не аутентифицируются — только userspace
// кода/данных нашего процесса.

#ifndef NK_PAC_ORACLE_H
#define NK_PAC_ORACLE_H

#include <stdint.h>
#include <stdbool.h>

#define NK_PAC_KEY_IA 0   /* generic indirect calls  */
#define NK_PAC_KEY_IB 1   /* stack / return context  */

/* Подпись ptr ключом IA, диверсификатор = modifier (64 бит). */
void *nk_pac_sign_ia(void *ptr, uint64_t modifier);
/* Подпись ptr ключом IB, диверсификатор = modifier (64 бит). */
void *nk_pac_sign_ib(void *ptr, uint64_t modifier);

/* Удаление PAC-бит (только masking, без проверки). User VA: верх 16 бит. */
void *nk_pac_strip_raw(void *ptr);

/* НЕ-фолтинг чек: ptr несут валидный PAC для (stripped(ptr), key, modifier)?
 * Метод: переподписать stripped и сравнить — без aut, без риска. */
bool nk_pac_check(void *ptr, uint64_t modifier, int key);

/* Self-test A2: подписать n разных указателей (реальные функции процесса),
 * проверить все через nk_pac_check + strip, вызвать через подписанный
 * указатель (autia + blr) и подтвердить side-effect.
 * results_out: opt, n булей (1 = полностью passed). Возврат: ok count. */
int nk_pac_oracle_selftest(int n, bool *results_out);

/* Один успешный вызов через подписанный указатель (для B1/B3 стабилизации).
 * Возврат: true если функция отработала (side-effect подтверждён). */
bool nk_pac_oracle_call_prove(void);

#endif
