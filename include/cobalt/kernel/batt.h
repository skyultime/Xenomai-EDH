#if !defined __BATT_H__
#define __BATT_H__

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
    bool message_integrity;
} Msg_battery;

extern Msg_battery battery_read_msg(void *arg);

#endif /* __BATT_H__ */
