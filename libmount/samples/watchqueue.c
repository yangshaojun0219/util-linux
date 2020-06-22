
#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <libmount.h>

int main(void) {
	struct libmnt_monitor *mn;
	struct libmnt_fs *fs, *aux;

	mnt_init_debug(0);

	fs = mnt_new_fs();
	aux = mnt_new_fs();
	mn = mnt_new_monitor();
	if (!fs || ! mn || !aux)
		goto err;

	if (mnt_monitor_enable_kernelwatch(mn, 1))
		goto err;

	do {
		printf("waiting for changes...\n");
		if (mnt_monitor_wait(mn, -1) < 0)
			break;

		printf(" notification detected\n");
		while (mnt_monitor_next_change(mn, NULL, NULL) == 0) {
			void *data;
			ssize_t sz;

			data = mnt_monitor_event_data(mn, MNT_MONITOR_TYPE_KERNELWATCH, &sz);
			do {
				int child;

				if (!mnt_kernelwatch_is_valid(data, sz) ||
				    !mnt_kernelwatch_is_mount(data))
					break;

				mnt_reset_fs(fs);
				mnt_fs_set_id(fs, mnt_kernelwatch_get_mount_id(data));
				mnt_fs_enable_fsinfo(fs, 1);

				child = mnt_kernelwatch_get_aux_id(data);
				if (child) {
					mnt_reset_fs(aux);
					mnt_fs_set_id(aux, child);
					mnt_fs_enable_fsinfo(aux, 1);

					printf(" fs [id=%d]: %s [modified child %3d: %s]\n",
						mnt_fs_get_id(fs), mnt_fs_get_target(fs),
						mnt_fs_get_id(aux), mnt_fs_get_target(aux));
				} else
					printf(" fs [id=%d]: %s\n",
						mnt_fs_get_id(fs), mnt_fs_get_target(fs));


				data = mnt_kernelwatch_next_data(data, &sz);
			} while (data);
			fflush(stdout);
		}
	} while (1);

	mnt_unref_fs(fs);
	mnt_unref_monitor(mn);
	return 0;
err:
	err(EXIT_FAILURE, "initialization failed");
}
