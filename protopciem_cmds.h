#ifndef PROTOPCIEM_CMDS_H
#define PROTOPCIEM_CMDS_H

#include <stdint.h>

#define CMD_OP_NOP 0x00
#define CMD_OP_CLEAR 0x01
#define CMD_OP_DRAW_LINE 0x02
#define CMD_OP_BLIT_RECT 0x03

struct cmd_header
{
    uint16_t opcode;
    uint16_t length;
} __attribute__((packed));

struct cmd_clear
{
    struct cmd_header hdr;
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t a;
} __attribute__((packed));

struct cmd_draw_line
{
    struct cmd_header hdr;
    uint16_t x0;
    uint16_t y0;
    uint16_t x1;
    uint16_t y1;
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t a;
} __attribute__((packed));

struct cmd_blit_rect
{
    struct cmd_header hdr;
    uint16_t x;
    uint16_t y;
    uint16_t width;
    uint16_t height;
} __attribute__((packed));

#endif /* PROTOPCIEM_CMDS_H */