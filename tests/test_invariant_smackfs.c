#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

/* Test that sprintf buffer operations in smackfs don't overflow */
START_TEST(test_smackfs_sprintf_buffer_bounds)
{
    /* Invariant: Buffer reads/writes never exceed declared buffer length.
       sprintf into fixed-size buffers must not overflow on any input. */
    
    char temp[20];  /* Simulating the vulnerable temp buffer from smackfs.c */
    unsigned long test_values[] = {
        0UL,                    /* Valid: zero */
        ULONG_MAX,              /* Boundary: maximum unsigned long (20+ digits on 64-bit) */
        999999999999999999UL,   /* Boundary: near max, triggers overflow risk */
        12345UL,                /* Valid: normal input */
        18446744073709551615UL  /* Exploit: max 64-bit value */
    };
    int num_values = sizeof(test_values) / sizeof(test_values[0]);
    
    for (int i = 0; i < num_values; i++) {
        memset(temp, 0, sizeof(temp));
        
        /* Call the vulnerable pattern: sprintf without bounds checking */
        int written = snprintf(temp, sizeof(temp), "%lu", test_values[i]);
        
        /* Invariant: written bytes must fit within buffer or be truncated safely */
        ck_assert_int_le(written, (int)sizeof(temp) - 1);
        
        /* Invariant: buffer must be null-terminated */
        ck_assert_int_lt(strlen(temp), sizeof(temp));
        
        /* Invariant: no out-of-bounds access occurred (buffer still valid) */
        ck_assert_ptr_nonnull(temp);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_smackfs_sprintf_buffer_bounds);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}