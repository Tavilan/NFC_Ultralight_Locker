#include <furi.h>
#include <furi_hal.h>
#include <furi_hal_nfc.h>

#define PAGE_LOCKS 0x02

static bool iso14443a_txrx(const uint8_t* tx, size_t tx_len_bytes,
                           uint8_t* rx, size_t rx_max, size_t* rx_len_bytes, size_t* rx_len_bits) {
    if(furi_hal_nfc_poller_tx(tx, tx_len_bytes * 8) != FuriHalNfcErrorNone) return false;
    FuriHalNfcError err = furi_hal_nfc_poller_rx_bits(rx, rx_max, rx_len_bits, 500);
    if(err != FuriHalNfcErrorNone) return false;
    *rx_len_bytes = (*rx_len_bits + 7) / 8;
    return true;
}

int32_t ultralight_lock_otp_app(void* p) {
    UNUSED(p);
    FURI_LOG_I("ULOTP", "Start");
    furi_hal_nfc_init();
    furi_hal_nfc_set_mode(FuriHalNfcModePoller);
    furi_hal_nfc_poller_start_discovery(FuriHalNfcTechIso14443a, 0, 0);

    Iso14443APrologue prologue;
    if(furi_hal_nfc_iso14443a_poller_select(&prologue) != FuriHalNfcErrorNone) {
        FURI_LOG_E("ULOTP", "No tag / select failed");
        goto done;
    }

    // READ 0x30 page 0x02 -> 16 bytes (pages 2..5)
    uint8_t cmd_read[] = {0x30, PAGE_LOCKS};
    uint8_t rd[32] = {0};
    size_t rd_bytes = 0, rd_bits = 0;
    if(!iso14443a_txrx(cmd_read, sizeof(cmd_read), rd, sizeof(rd), &rd_bytes, &rd_bits) || rd_bytes < 16) {
        FURI_LOG_E("ULOTP", "READ failed");
        goto done;
    }

    uint8_t p2_b0 = rd[0], p2_b1 = rd[1], p2_b2 = rd[2], p2_b3 = rd[3];
    uint8_t new_b2 = p2_b2 | 0x08; // set b3 -> lock OTP (page 3)
    if(new_b2 == p2_b2) {
        FURI_LOG_I("ULOTP", "OTP already locked");
        goto done;
    }

    // WRITE 0xA2 page 0x02 with 4 bytes
    uint8_t cmd_write[6] = {0xA2, PAGE_LOCKS, p2_b0, p2_b1, new_b2, p2_b3};
    uint8_t ack_buf[2] = {0};
    size_t ack_bytes = 0, ack_bits = 0;
    if(!iso14443a_txrx(cmd_write, sizeof(cmd_write), ack_buf, sizeof(ack_buf), &ack_bytes, &ack_bits)) {
        FURI_LOG_E("ULOTP", "WRITE no resp");
        goto done;
    }
    // Ultralight ACK = 0x0A (4 bits)
    if(!(ack_bits == 4 && ((ack_buf[0] & 0x0F) == 0x0A))) {
        FURI_LOG_E("ULOTP", "WRITE NAK");
        goto done;
    }

    // Verify
    if(!iso14443a_txrx(cmd_read, sizeof(cmd_read), rd, sizeof(rd), &rd_bytes, &rd_bits) || rd_bytes < 16) {
        FURI_LOG_E("ULOTP", "Post-READ failed");
        goto done;
    }
    if((rd[2] & 0x08) == 0x08) FURI_LOG_I("ULOTP", "✅ OTP locked");
    else FURI_LOG_W("ULOTP", "⚠️ Verify failed");

done:
    furi_hal_nfc_poller_stop();
    furi_hal_nfc_deinit();
    FURI_LOG_I("ULOTP", "Done");
    return 0;
}
