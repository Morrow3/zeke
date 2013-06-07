/**
 *******************************************************************************
 * @file    semaphore.h
 * @author  Olli Vanhoja
 * @brief   Semaphore
 *******************************************************************************
 */

#pragma once
#ifndef SEMAPHORE_H
#define SEMAPHORE_H

/**
 * Semaphore control block
 */
typedef struct os_semaphore_cb {
    uint32_t s;
    uint32_t count;
} os_semaphore_cb_t;

#endif /* SEMAPHORE_H */
