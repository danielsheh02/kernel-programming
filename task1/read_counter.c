#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h> // copy_to_user, copy_from_user

#define DEVICE_NAME "read_counter"

static int major;

static int counter = 0;  // счётчик обращений на чтение

// open
static int rc_open(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "read_counter: device opened\n");
    return 0;
}

// release
static int rc_release(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "read_counter: device closed\n");
    return 0;
}

// read
static ssize_t rc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    printk(KERN_INFO "read_counter: read file\n");

    // если пользователь уже читал этот буфер, возвращаем 0 (EOF), как правило происходит 2 вызова rc_read
    if (*ppos > 0) {
        printk(KERN_INFO "read_counter: already read file\n");
        return 0;
    }

    char msg[32];
    int len;
    
    counter++; // увеличиваем счётчик
    len = snprintf(msg, sizeof(msg), "%d\n", counter);

    if (copy_to_user(buf, msg, len))
        return -EFAULT;

    *ppos = len; // сдвигаем файловую позицию
    return len;
}

// write (не поддерживается)
static ssize_t rc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    return -EOPNOTSUPP;
}

static struct file_operations fops = {
    .owner   = THIS_MODULE,
    .open    = rc_open,
    .release = rc_release,
    .read    = rc_read,
    .write   = rc_write,
};

// загрузка модуля
static int __init rc_init(void)
{

    // Запрашиваем major number у ядра
    major = register_chrdev(0, DEVICE_NAME, &fops);
    if (major < 0) {
        printk(KERN_ALERT "failed to register a major number\n");
        return major;
    }


    printk(KERN_INFO "read_counter: module loaded, major=%d\n", major);
    printk(KERN_INFO "Create device file: mknod /dev/%s c %d 0\n", DEVICE_NAME, major);

    return 0;
}

// выгрузка модуля
static void __exit rc_exit(void)
{
    unregister_chrdev(major, DEVICE_NAME);
    printk(KERN_INFO "read_counter: module unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel Programming Task");
MODULE_DESCRIPTION("Char driver that counts read() calls");

module_init(rc_init);
module_exit(rc_exit);

