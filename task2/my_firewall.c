#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/rwlock.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/inet.h>
#include <linux/string.h>

#define DEVICE_NAME "my_firewall"
#define CLASS_NAME  "my_fw"

#define READ_BUF_SIZE 8192

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chehade Daniel");
MODULE_DESCRIPTION("Mini-firewall (Netfilter)");
MODULE_VERSION("1.0");

struct blocked_ip {
    struct list_head list;
    __be32 ip;
};

static LIST_HEAD(blocked_ip_list);

static DEFINE_RWLOCK(ip_list_lock);

/* Netfilter hook ops */
static struct nf_hook_ops my_nfho;

/* Char device structures */
static dev_t dev_number;
static struct cdev my_cdev;
static struct class *my_class = NULL;
static struct device *my_device = NULL;

static struct blocked_ip *find_blocked_ip(__be32 ip)
{
    struct blocked_ip *entry;
    list_for_each_entry(entry, &blocked_ip_list, list) {
        if (entry->ip == ip)
            return entry;
    }
    return NULL;
}

static int add_ip_to_block(__be32 ip)
{
    struct blocked_ip *e;

    if (find_blocked_ip(ip))
        return -EEXIST;

    e = kmalloc(sizeof(*e), GFP_KERNEL);
    if (!e)
        return -ENOMEM;

    INIT_LIST_HEAD(&e->list);
    e->ip = ip;
    list_add_tail(&e->list, &blocked_ip_list);
    return 0;
}

static int del_ip_from_block(__be32 ip)
{
    struct blocked_ip *e;

    e = find_blocked_ip(ip);
    if (!e)
        return -ENOENT;

    list_del(&e->list);
    kfree(e);
    return 0;
}

/* --- Netfilter hook --- */
static unsigned int my_firewall_hook_func(void *priv,
                                         struct sk_buff *skb,
                                         const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    __be32 src;

    if (!skb)
        return NF_ACCEPT;

    if (skb->protocol != htons(ETH_P_IP))
        return NF_ACCEPT;

    ip_header = ip_hdr(skb);
    if (!ip_header)
        return NF_ACCEPT;

    src = ip_header->saddr;

    read_lock(&ip_list_lock);
    if (find_blocked_ip(src)) {
        /* pr_info("my_firewall: dropping packet from %pI4\n", &src); */
        read_unlock(&ip_list_lock);
        return NF_DROP;
    }
    read_unlock(&ip_list_lock);

    return NF_ACCEPT;
}

static ssize_t myfw_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos)
{
    char *kbuf;
    size_t written = 0;
    int ret = 0;
    struct blocked_ip *entry;

    if (!buf || !ppos)
        return -EINVAL;

    if (*ppos > 0)
        return 0;

    kbuf = kmalloc(READ_BUF_SIZE, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    kbuf[0] = '\0';

    read_lock(&ip_list_lock);
    list_for_each_entry(entry, &blocked_ip_list, list) {
        int l = snprintf(kbuf + written, READ_BUF_SIZE - written, "%pI4\n", &entry->ip);
        if (l < 0) {
            ret = -EOVERFLOW;
            goto out_unlock;
        }
        written += l;
        if (written >= READ_BUF_SIZE - 1)
            break;
    }
out_unlock:
    read_unlock(&ip_list_lock);

    if (ret < 0) {
        kfree(kbuf);
        return ret;
    }

    if (count < written) {
        if (copy_to_user(buf, kbuf, count)) {
            kfree(kbuf);
            return -EFAULT;
        }
        *ppos += count;
        kfree(kbuf);
        return count;
    } else {
        if (copy_to_user(buf, kbuf, written)) {
            kfree(kbuf);
            return -EFAULT;
        }
        *ppos += written;
        kfree(kbuf);
        return written;
    }
}

#define WRITE_BUF_SIZE 128
static ssize_t myfw_write(struct file *filp, const char __user *buf, size_t count, loff_t *ppos)
{
    char kbuf[WRITE_BUF_SIZE];
    char cmd[8];
    char ipstr[32];
    __be32 ip;
    int scanned;

    if (count == 0)
        return 0;

    if (count >= WRITE_BUF_SIZE)
        return -EINVAL;

    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;

    kbuf[count] = '\0';

    if (kbuf[count-1] == '\n')
        kbuf[count-1] = '\0';

    scanned = sscanf(kbuf, "%7s %31s", cmd, ipstr);

    if (scanned != 2) {
        pr_info("my_firewall: invalid command. Use: add/del <ip>\n");
        return -EINVAL;
    }

    ip = in_aton(ipstr);

    if (strcmp(cmd, "add") == 0) {
        int err;
        write_lock(&ip_list_lock);
        err = add_ip_to_block(ip);
        write_unlock(&ip_list_lock);
        if (err == -EEXIST) {
            pr_info("my_firewall: %pI4 already in block list\n", &ip);
            return count;
        } else if (err) {
            pr_err("my_firewall: failed to add %pI4 (err=%d)\n", &ip, err);
            return err;
        } else {
            pr_info("my_firewall: added %pI4 to block list\n", &ip);
            return count;
        }
    } else if (strcmp(cmd, "del") == 0) {
        int err;
        write_lock(&ip_list_lock);
        err = del_ip_from_block(ip);
        write_unlock(&ip_list_lock);
        if (err == -ENOENT) {
            pr_info("my_firewall: %pI4 not found in block list\n", &ip);
            return count;
        } else if (err) {
            pr_err("my_firewall: failed to delete %pI4 (err=%d)\n", &ip, err);
            return err;
        } else {
            pr_info("my_firewall: removed %pI4 from block list\n", &ip);
            return count;
        }
    } else {
        pr_info("my_firewall: unknown command '%s'\n", cmd);
        return -EINVAL;
    }
}

static int myfw_open(struct inode *inode, struct file *file)
{
    pr_info("my_firewall: device opened\n");
    return 0;
}

static int myfw_release(struct inode *inode, struct file *file)
{
    pr_info("my_firewall: device closed\n");
    return 0;
}

static const struct file_operations myfw_fops = {
    .owner = THIS_MODULE,
    .read = myfw_read,
    .write = myfw_write,
    .open = myfw_open,
    .release = myfw_release,
};

static int __init myfw_init(void)
{
    int ret;

    pr_info("my_firewall: init\n");

    /* 1) Зарегистрировать char device */
    ret = alloc_chrdev_region(&dev_number, 0, 1, DEVICE_NAME);
    if (ret) {
        pr_err("my_firewall: alloc_chrdev_region failed: %d\n", ret);
        return ret;
    }

    cdev_init(&my_cdev, &myfw_fops);
    ret = cdev_add(&my_cdev, dev_number, 1);
    if (ret) {
        pr_err("my_firewall: cdev_add failed: %d\n", ret);
        unregister_chrdev_region(dev_number, 1);
        return ret;
    }

    my_class = class_create(CLASS_NAME);
    if (IS_ERR(my_class)) {
        pr_err("my_firewall: class_create failed\n");
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev_number, 1);
        return PTR_ERR(my_class);
    }

    my_device = device_create(my_class, NULL, dev_number, NULL, DEVICE_NAME);
    if (IS_ERR(my_device)) {
        pr_err("my_firewall: device_create failed\n");
        class_destroy(my_class);
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev_number, 1);
        return PTR_ERR(my_device);
    }

    pr_info("my_firewall: device created: /dev/%s (major=%d, minor=%d)\n",
            DEVICE_NAME, MAJOR(dev_number), MINOR(dev_number));

    /* 2) Регистрируем Netfilter hook */
    my_nfho.hook = my_firewall_hook_func;
    my_nfho.pf = PF_INET;
    my_nfho.hooknum = NF_INET_PRE_ROUTING;
    my_nfho.priority = NF_IP_PRI_FIRST;

    ret = nf_register_net_hook(&init_net, &my_nfho);
    if (ret) {
        pr_err("my_firewall: nf_register_net_hook failed: %d\n", ret);
        device_destroy(my_class, dev_number);
        class_destroy(my_class);
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev_number, 1);
        return ret;
    }

    pr_info("my_firewall: netfilter hook registered\n");
    return 0;
}

static void __exit myfw_exit(void)
{
    struct blocked_ip *entry, *tmp;

    pr_info("my_firewall: exit\n");

    /* 1) Удаляем Netfilter hook */
    nf_unregister_net_hook(&init_net, &my_nfho);
    pr_info("my_firewall: netfilter hook unregistered\n");

    /* 2) Удаляем все элементы списка под write_lock */
    write_lock(&ip_list_lock);
    list_for_each_entry_safe(entry, tmp, &blocked_ip_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    write_unlock(&ip_list_lock);

    /* 3) Удаляем устройство */
    device_destroy(my_class, dev_number);
    class_destroy(my_class);
    cdev_del(&my_cdev);
    unregister_chrdev_region(dev_number, 1);

    pr_info("my_firewall: unloaded\n");
}

module_init(myfw_init);
module_exit(myfw_exit);
