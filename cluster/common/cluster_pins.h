#pragma once

#define CL_I2C_PORT     0
#define CL_I2C_SDA_GPIO 11
#define CL_I2C_SCL_GPIO 12
#define CL_I2C_HZ       100000

#define CL_BRAIN_ADDR   0x10
#define CL_S3_ADDR      0x13

#define CL_ARM_POOL     { 0x11, 0x12, 0x14, 0x15, 0x16, 0x17 }
#define CL_ARM_POOL_N   6
#define CL_ARM1_ADDR    0x11

#define CL_LCD_SPI_HOST 1
#define CL_LCD_MOSI     2
#define CL_LCD_MISO     7
#define CL_LCD_SCK      6
