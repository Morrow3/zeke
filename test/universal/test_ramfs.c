/**
 * @file test_ramfs.c
 * @brief Test ramfs.
 */

#include <punit.h>
#include <kmalloc.h>
#include <dirent.h> /* NOTE: This includes our own implementation of dirent.h
                     *       and types.h and this might be bit hazardous. */
#include "sim_kmheap.h"
#include <fs/fs.h>

/**
 * Create a kmalloc'd string.
 * @param string that should be kmalloc'd.
 * @return Returns a pointer to the kmalloc'd string.
 */
#define KM_STRING(str) strcpy(kmalloc(strlen(str) + 1), str)

static void walk_dirtree(vnode_t * vnode, int ind);

extern fs_t ramfs_fs;


static void setup()
{
    setup_kmalloc();
    ramfs_fs.sbl_head = 0;
}

static void teardown()
{
    teardown_kmalloc();
}

static char * test_mount(void)
{
#define MOUNT_POINT "/tmp"
#define MODE_FLAGS 0
    fs_superblock_t * sb;
    superblock_lnode_t * tmp;
    size_t i;

    pu_test_description("Test that newly created/mounted superblock is initialized correctly.");

    sb = ramfs_fs.mount(KM_STRING(MOUNT_POINT), MODE_FLAGS, 0, "");
    pu_assert("superblock list is started.", ramfs_fs.sbl_head != 0);
    pu_assert_ptr_equal("Correct head entry.", &(ramfs_fs.sbl_head->sbl_sb), sb);
    pu_assert_equal("Mode flags are equal.", sb->mode_flags, MODE_FLAGS);
    pu_assert("root vnode is set", sb->root != 0);
    pu_assert_str_equal("Mount point equals", sb->mtpt_path, MOUNT_POINT);

    /* Test that sb list works for multiple mounts */
    for (i = 0; i < 3; i++) {
        sb = ramfs_fs.mount(KM_STRING(MOUNT_POINT), MODE_FLAGS, 0, "");
        pu_assert("sb allocated.", sb != 0);
        tmp = ramfs_fs.sbl_head;
        while (&(tmp->sbl_sb) != sb) {
            tmp = tmp->next;
            if (tmp == 0)
                pu_assert_fail("superblock sb not found from the sb_list of ramfs_fs.");
        }
    }

#undef MOUNT_POINT
#undef MODE_FLAGS

    return 0;
}

static char * test_lookup(void)
{
#define MOUNT_POINT "/tmp"
#define MODE_FLAGS 0
#define DOT "."
#define DOTDOT ".."
#define F_NAME "cefijefj"
    fs_superblock_t * sb;
    vnode_t * root;
    vnode_t * result;

    pu_test_description("Test vnode lookup by hard link name works.");

    sb = ramfs_fs.mount(KM_STRING(MOUNT_POINT), MODE_FLAGS, 0, "");
    root = sb->root;
    pu_assert("Root exist", root != 0);

    root->vnode_ops->lookup(root, DOT, sizeof(DOT) - 1, &result);
    pu_assert_ptr_equal(DOT" -> root", result, root);
    pu_assert_equal("Lookup ok",
            root->vnode_ops->lookup(root, DOTDOT, sizeof(DOTDOT) - 1, &result), 0);
    pu_assert_ptr_equal(DOTDOT" -> root", result, root);

    pu_assert("Doesn't find a link that doesn't exist.",
            root->vnode_ops->lookup(root, F_NAME, sizeof(F_NAME) - 1, &result) != 0);


#undef MOUNT_POINT
#undef MODE_FLAGS
#undef DOT
#undef DOTDOT
#undef F_NAME
    return 0;
}

static char * test_create_inode(void)
{
#define MOUNT_POINT "/tmp"
#define MODE_FLAGS 0
#define TEST_FILE "test_file"
    fs_superblock_t * sb;
    vnode_t * root;
    vnode_t * filenode;
    vnode_t * result;

    pu_test_description("Test that inode can be created and then retrieved by its number.");

    sb = ramfs_fs.mount(KM_STRING(MOUNT_POINT), MODE_FLAGS, 0, "");
    root = sb->root;
    pu_assert("Root exist", root != 0);

    root->vnode_ops->create(root, TEST_FILE, sizeof(TEST_FILE) - 1, &filenode);
    pu_assert("File was created.", filenode != 0);
    root->vnode_ops->lookup(root, TEST_FILE, sizeof(TEST_FILE) - 1, &result);
    pu_assert_ptr_equal("Found previously created vnode.", result, filenode);

#undef MOUNT_POINT
#undef MODE_FLAGS
#undef TEST_FILE
    return 0;
}

static char * test_create_multiple(void)
{
#define MOUNT_POINT "/tmp"
#define MODE_FLAGS 0
#define TST1 "test_file"
#define TST2 "tt"
#define TST3 "ttt"
#define TST4 "uef"
    fs_superblock_t * sb;
    vnode_t * root;
    vnode_t * filenode1;
    vnode_t * filenode2;
    vnode_t * filenode3;
    vnode_t * filenode4;
    vnode_t * result;

    pu_test_description("Test that inode can be created and then retrieved by its number.");

    sb = ramfs_fs.mount(KM_STRING(MOUNT_POINT), MODE_FLAGS, 0, "");
    root = sb->root;
    pu_assert("Root exist", root != 0);

    root->vnode_ops->create(root, TST1, sizeof(TST1) - 1, &filenode1);
    pu_assert("File was created.", filenode1 != 0);
    root->vnode_ops->create(root, TST2, sizeof(TST2) - 1, &filenode2);
    pu_assert("File was created.", filenode2 != 0);
    root->vnode_ops->create(root, TST3, sizeof(TST3) - 1, &filenode3);
    pu_assert("File was created.", filenode3 != 0);
    root->vnode_ops->create(root, TST4, sizeof(TST4) - 1, &filenode4);
    pu_assert("File was created.", filenode4 != 0);

    root->vnode_ops->lookup(root, TST1, sizeof(TST1) - 1, &result);
    pu_assert_ptr_equal("Found previously created vnode.", result, filenode1);

    root->vnode_ops->lookup(root, TST2, sizeof(TST2) - 1, &result);
    pu_assert_ptr_equal("Found previously created vnode.", result, filenode2);

    root->vnode_ops->lookup(root, TST3, sizeof(TST3) - 1, &result);
    pu_assert_ptr_equal("Found previously created vnode.", result, filenode3);

    root->vnode_ops->lookup(root, TST4, sizeof(TST4) - 1, &result);
    pu_assert_ptr_equal("Found previously created vnode.", result, filenode4);

#undef MOUNT_POINT
#undef MODE_FLAGS
#undef TST1
#undef TST2
#undef TST3
#undef TST4
    return 0;
}

static char * test_write_read_reg(void)
{
#define MOUNT_POINT "/tmp"
#define MODE_FLAGS 0
#define FILENAME "test"
#define str_src "QAZWSXEDCEDCRFV"
    fs_superblock_t * sb;
    vnode_t * root;
    vnode_t * file;
    char str_dst[sizeof(str_src) + 1];
    size_t bytes_written, bytes_read;
    const off_t file_start = 0;

    str_dst[sizeof(str_src)] = '\0';

    pu_test_description("Test that regular files can be writen and read");

    sb = ramfs_fs.mount(KM_STRING(MOUNT_POINT), MODE_FLAGS, 0, "");
    root = sb->root;
    pu_assert("Root exist", root != 0);

    root->vnode_ops->create(root, FILENAME, sizeof(FILENAME) - 1, &file);
    pu_assert("File was created.", file != 0);

    bytes_written = file->vnode_ops->write(file, &file_start, str_src, sizeof(str_src));
    pu_assert_equal("Bytes written equals length of given buffer.",
            (int)bytes_written, (int)sizeof(str_src));

    bytes_read = file->vnode_ops->read(file, &file_start, str_dst, sizeof(str_src));
    pu_assert_equal("Bytes read equals length of the original buffer.",
            (int)bytes_read, (int)sizeof(str_src));

    pu_assert_str_equal("String read from the file equal the original string.",
            str_dst, str_src);

#undef MOUNT_POINT
#undef MODE_FLAGS
#undef FILENAME
#undef str_src
    return 0;
}

static char * test_mkdir(void)
{
#define MOUNT_POINT "/tmp"
#define MODE_FLAGS 0
#define DIR_1 "a"
#define DIR_2 "b"
#define DIR_3 "c"
    fs_superblock_t * sb;
    vnode_t * root;
    vnode_t * result;
    vnode_t * result1;

    pu_test_description("Test mkdir.");

    sb = ramfs_fs.mount(KM_STRING(MOUNT_POINT), MODE_FLAGS, 0, "");
    root = sb->root;
    pu_assert("Root exist", root != 0);
    pu_assert_equal("Type is dir", S_ISDIR(root->mode), 1);

    /* Create dir a */
    pu_assert_equal("Dir created",
            root->vnode_ops->mkdir(root,  DIR_1, sizeof(DIR_1) - 1), 0);
    pu_assert_equal("Lookup ok",
            root->vnode_ops->lookup(root, DIR_1, sizeof(DIR_1) - 1, &result), 0);
    pu_assert("Found new dir", result != 0);
    pu_assert_equal("Type is dir", S_ISDIR(result->mode), 1);

    /* Create dir b */
    pu_assert_equal("Dir created",
            result->vnode_ops->mkdir(result,  DIR_2, sizeof(DIR_2) - 1), 0);
    pu_assert_equal("Lookup ok",
            result->vnode_ops->lookup(result, DIR_2, sizeof(DIR_2) - 1, &result1), 0);
    pu_assert("Found new dir", result1 != 0);
    pu_assert_equal("Type is dir", S_ISDIR(result1->mode), 1);

    /* Create dir c */
    pu_assert_equal("Dir created",
            result->vnode_ops->mkdir(result,  DIR_3, sizeof(DIR_3) - 1), 0);
    pu_assert_equal("Lookup ok",
            result->vnode_ops->lookup(result, DIR_3, sizeof(DIR_3) - 1, &result), 0);
    pu_assert("Found new dir", result != 0);
    pu_assert_equal("Type is dir", S_ISDIR(result->mode), 1);
#undef MOUNT_POINT
#undef MODE_FLAGS
#undef DIR_1
#undef DIR_2
#undef DIR_3

    return 0;
}

static char * test_readdir(void)
{
#define MOUNT_POINT "/tmp"
#define MODE_FLAGS 0
#define DIR_1 "a"
#define DIR_2 "b"
#define DIR_3 "c"
    fs_superblock_t * sb;
    vnode_t * root;
    vnode_t * result;
    vnode_t * result1;
    vnode_t * file;

    pu_test_description("Test mkdir.");

    sb = ramfs_fs.mount(KM_STRING(MOUNT_POINT), MODE_FLAGS, 0, "");
    root = sb->root;
    pu_assert("Root exist", root != 0);

    /* Same as test_mkdir... */
    /* Create dir a */
    pu_assert_equal("Dir created",
            root->vnode_ops->mkdir(root,  DIR_1, sizeof(DIR_1) - 1), 0);
    pu_assert_equal("Lookup ok",
            root->vnode_ops->lookup(root, DIR_1, sizeof(DIR_1) - 1, &result), 0);
    pu_assert("Found new dir", result != 0);

    /* Create dir b */
    pu_assert_equal("Dir created",
            result->vnode_ops->mkdir(result,  DIR_2, sizeof(DIR_2) - 1), 0);
    pu_assert_equal("Lookup ok",
            result->vnode_ops->lookup(result, DIR_2, sizeof(DIR_2) - 1, &result1), 0);
    pu_assert("Found new dir", result1 != 0);

    /* Create dir c */
    pu_assert_equal("Dir created",
            result->vnode_ops->mkdir(result,  DIR_3, sizeof(DIR_3) - 1), 0);
    pu_assert_equal("Lookup ok",
            result->vnode_ops->lookup(result, DIR_3, sizeof(DIR_3) - 1, &result), 0);
    pu_assert("Found new dir", result != 0);
#undef MOUNT_POINT
#undef MODE_FLAGS
#undef DIR_1
#undef DIR_2
#undef DIR_3

    /* ...until here, this is the actula readdir test. */
#define FILENAME "file.txt"
    result->vnode_ops->create(root, FILENAME, sizeof(FILENAME) - 1, &file);
    pu_assert("File was created.", file != 0);
#undef FILENAME
    /* Some more files just for fun */
#define FILENAME "README.txt"
    result->vnode_ops->create(result, FILENAME, sizeof(FILENAME) - 1, &file);
    pu_assert("File was created.", file != 0);
#undef FILENAME
#define FILENAME "system.bin"
    result->vnode_ops->create(result, FILENAME, sizeof(FILENAME) - 1, &file);
    pu_assert("File was created.", file != 0);
#undef FILENAME
#define FILENAME "my other.file"
    result1->vnode_ops->create(result1, FILENAME, sizeof(FILENAME) - 1, &file);
    pu_assert("File was created.", file != 0);
#undef FILENAME

    walk_dirtree(root, 1);

    return 0;
}

#define iprintf(indent, fmt, ...) (printf("%*s" fmt, indent, " ", __VA_ARGS__))
static void walk_dirtree(vnode_t * vnode, int ind)
{
    struct dirent d;
    fs_superblock_t * sb = vnode->sb;
    vnode_t * vnode_child;

    /* TODO This doesn't actually test anything by now */

    d.d_off = 0x00000000FFFFFFFF; /* TODO initializer? */

    while(!vnode->vnode_ops->readdir(vnode, &d)) {
#ifdef PU_REPORT_ORIENTED
        iprintf(ind, "|- %s\t", d.d_name);
#endif
        if (vnode->vnode_num == d.d_ino) { /* Skip if cycle. */
            printf("[hard link to .]\n");
            continue;
        }

        /* Check if found node was a directory */
        if(!sb->get_vnode(sb, &(d.d_ino), &vnode_child)) {
            //printf("walk, mode: %u, node: %u\n", vnode_child->mode, vnode_child->vnode_num);
            switch (vnode_child->mode & S_IFMT) {
                case S_IFREG:
                    printf("[regular file]\n");
                    break;
                case S_IFDIR:
                    printf(" [dir]\n");
                    walk_dirtree(vnode_child, ind + 3);
                    break;
                default:
                    printf("[?]\n");
            }

            /* Destroy the reference. */
            ramfs_delete_vnode(vnode_child);
        } else printf("\n");
    }
}

static void all_tests() {
    pu_def_test(test_mount, PU_RUN);
    pu_def_test(test_lookup, PU_RUN);
    pu_def_test(test_create_inode, PU_RUN);
    pu_def_test(test_create_multiple, PU_RUN);
    pu_def_test(test_write_read_reg, PU_RUN);
    pu_def_test(test_mkdir, PU_RUN);
    pu_def_test(test_readdir, PU_RUN);
}

int main(int argc, char **argv)
{
    return pu_run_tests(&all_tests);
}
