#!/bin/bash -x

git send-email --to=linux-kernel@vger.kernel.org --cc=iovisor-dev@lists.iovisor.org --cc=kernel-team@android.com $1
