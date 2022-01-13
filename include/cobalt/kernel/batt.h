#if !defined __BATT_H__
#define __BATT_H__

#include <linux/types.h>

int batt_init (void);
int batt_deinit(void);

/* \stuct Msg_battery
 *
 * \brief struct Msg_battery
 *
 */
typedef struct {
    int capacity;
    int chargenow;
    int chargefull;
    int battery_size;
    int energy_production;
    bool message_integrity;

} Msg_battery;

#define BATTERY_SIZE_MAX_VALUE (100)
#define EP_MAX_VALUE (100)


extern Msg_battery battery_read_msg(void);

#endif /* __BATT_H__ */
