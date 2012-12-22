/**
 *******************************************************************************
 * @file    kernel.h
 * @author  Olli Vanhoja
 * @brief   Zero Kernel
 *
 *******************************************************************************
 */

/** @addtogroup Kernel
  * @{
  */

#include "stm32f0_interrupt.h"

#include "sched.h"
#include "syscall.h"
#include "kernel.h"

void kernel_init(void)
{
    interrupt_init_module();
}

void kernel_start(void)
{
    sched_init();
    sched_start();
    while(1) { }
}

/** @todo doesn't pass argument now */
int osThreadCreate(osThreadDef_t * thread_def, void * argument)
{
    int result;

    result = (int)syscall(KERNEL_SYSCALL_SCHED_THREAD_CREATE, (void *)thread_def);
    SCB->ICSR |= SCB_ICSR_PENDSVSET_Msk; /* Set PendSV pending status */
    asm volatile("DSB\n" /* Ensure write is completed
                          * (architecturally required, but not strictly
                          * required for existing Cortex-M processors) */
                 "ISB\n" /* Ensure PendSV is executed */
                 );

    return result;
}

osStatus osDelay(uint32_t millisec)
{
    osStatus result;

    result = (osStatus)syscall(KERNEL_SYSCALL_SCHED_DELAY, &millisec);
    SCB->ICSR |= SCB_ICSR_PENDSVSET_Msk; /* Set PendSV pending status */
    asm volatile("DSB\n" /* Ensure write is completed
                          * (architecturally required, but not strictly
                          * required for existing Cortex-M processors) */
                 "ISB\n" /* Ensure PendSV is executed */
                 );

    return result;
}

/**
  * @}
  */