/*
 * thread.c
 *
 * Copyright (c) 2012 Martin Szulecki All Rights Reserved.
 * Copyright (c) 2012 Nikias Bassen All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "thread.h"

int thread_new(thread_t *thread, thread_func_t thread_func, void* data)
{
#ifdef WIN32
	HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)thread_func, data, 0, NULL);
	if (th == NULL) {
		return -1;
	}
	*thread = th;
	return 0;
#else
	int res = pthread_create(thread, NULL, thread_func, data);
	return res;
#endif
}

void thread_free(thread_t thread)
{
#ifdef WIN32
	CloseHandle(thread);
#endif
}

void thread_join(thread_t thread)
{
	/* wait for thread to complete */
#ifdef WIN32
	WaitForSingleObject(thread, INFINITE);
#else
	pthread_join(thread, NULL);
#endif
}

int thread_alive(thread_t thread)
{
	if (!thread)
		return 0;
#ifdef WIN32
	return WaitForSingleObject(thread, 0) == WAIT_TIMEOUT;
#else
	return pthread_kill(thread, 0) == 0;
#endif
}

void mutex_init(mutex_t* mutex)
{
#ifdef WIN32
	InitializeCriticalSection(mutex);
#else
	pthread_mutex_init(mutex, NULL);
#endif
}

void mutex_destroy(mutex_t* mutex)
{
#ifdef WIN32
	DeleteCriticalSection(mutex);
#else
	pthread_mutex_destroy(mutex);
#endif
}

void mutex_lock(mutex_t* mutex)
{
#ifdef WIN32
	EnterCriticalSection(mutex);
#else
	pthread_mutex_lock(mutex);
#endif
}

void mutex_unlock(mutex_t* mutex)
{
#ifdef WIN32
	LeaveCriticalSection(mutex);
#else
	pthread_mutex_unlock(mutex);
#endif
}

void thread_once(thread_once_t *once_control, void (*init_routine)(void))
{
#ifdef WIN32
	while (InterlockedExchange(&(once_control->lock), 1) != 0) {
		Sleep(1);
	}
	if (!once_control->state) {
		once_control->state = 1;
		init_routine();
	}
	InterlockedExchange(&(once_control->lock), 0);
#else
	pthread_once(once_control, init_routine);
#endif
}

void cond_init(cond_t* cond)
{
#ifdef WIN32
	cond->sem = CreateSemaphore(NULL, 0, 32767, NULL);
#else
	pthread_cond_init(cond, NULL);
#endif
}

void cond_destroy(cond_t* cond)
{
#ifdef WIN32
	CloseHandle(cond->sem);
#else
	pthread_cond_destroy(cond);
#endif
}

int cond_signal(cond_t* cond)
{
#ifdef WIN32
	int result = 0;
	if (!ReleaseSemaphore(cond->sem, 1, NULL)) {
		result = -1;
	}
	return result;
#else
	return pthread_cond_signal(cond);
#endif
}

int cond_wait(cond_t* cond, mutex_t* mutex)
{
#ifdef WIN32
	mutex_unlock(mutex);
	WaitForSingleObject(cond->sem, INFINITE);
#else
	return pthread_cond_wait(cond, mutex);
#endif
}

int cond_wait_timeout(cond_t* cond, mutex_t* mutex, unsigned int timeout_ms)
{
#ifdef WIN32
	mutex_unlock(mutex);
	WaitForSingleObject(cond->sem, timeout_ms);
#else
	struct timespec ts;
	struct timeval now;
	gettimeofday(&now, NULL);

	ts.tv_sec = now.tv_sec + timeout_ms / 1000;
	ts.tv_nsec = now.tv_usec * 1000 + 1000 * 1000 * (timeout_ms % 1000);
	ts.tv_sec += ts.tv_nsec / (1000 * 1000 * 1000);
	ts.tv_nsec %= (1000 * 1000 * 1000);

	return pthread_cond_timedwait(cond, mutex, &ts);
#endif
}
