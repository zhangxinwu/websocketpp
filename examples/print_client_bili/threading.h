//
// Created by xinwu-pc on 2022/12/6.
//

#ifndef WILIWILI_THREADING_H
#define WILIWILI_THREADING_H

#include <mutex>
#include <thread>
#include <vector>
#include <functional>
#include <chrono>

class Threading {
public:
    Threading() {
        // 启动执行任务的线程
        start();
    }

    // 将函数添加到同步任务队列
    void sync(const std::function<void()> &func) {
        // 上锁，保证线程安全
        std::lock_guard<std::mutex> lock(m_sync_mutex);
        m_sync_functions.push_back(func);
    }

    // 将函数添加到异步任务队列
    void async(const std::function<void()> &func) {
        // 上锁，保证线程安全
        std::lock_guard<std::mutex> lock(m_async_mutex);
        m_async_tasks.push_back(func);
    }

    // 将函数添加到延迟任务队列，在指定的毫秒数后执行
    void delay(long milliseconds, const std::function<void()> &func) {
        // 上锁，保证线程安全
        std::lock_guard<std::mutex> lock(m_delay_mutex);

        // 创建延迟任务对象
        DelayOperation delay_op;
        delay_op.milliseconds = milliseconds;
        delay_op.func = func;
        delay_op.created_time = std::chrono::system_clock::now();
        m_delay_tasks.push_back(delay_op);
    }

    // 启动执行任务的线程
    void start() {
        // 如果任务线程未启动，则启动它
        if (!m_task_thread.joinable()) {
            m_task_thread = std::thread(&Threading::taskLoop, this);
        }
    }

    // 停止执行任务的线程
    void stop() {
        // 将任务线程的活动状态设置为false
        task_loop_active = false;

        // 等待任务线程完成
        m_task_thread.join();
    }

    // 执行所有同步任务
    void performSyncTasks() {
        // 上锁，保证线程安全
        std::lock_guard<std::mutex> lock(m_sync_mutex);
        // 执行所有同步任务
        for (auto &func: m_sync_functions) {
            func();
        }

        // 清空同步任务队列
        m_sync_functions.clear();
    }

    // 析构函数，在对象销毁时调用
    ~Threading() {
        // 停止任务线程
        stop();
    }

private:
    // 定义延迟任务结构
    struct DelayOperation {
        // 延迟的毫秒数
        long milliseconds;

        // 任务函数
        std::function<void()> func;

        // 任务创建时间
        std::chrono::system_clock::time_point created_time;
    };


    // 保护同步任务队列的互斥锁
    std::mutex m_sync_mutex;

    // 同步任务队列
    std::vector<std::function<void()>> m_sync_functions;

    // 保护异步任务队列的互斥锁
    std::mutex m_async_mutex;

    // 异步任务队列
    std::vector<std::function<void()>> m_async_tasks;

    // 保护延迟任务队列的互斥锁
    std::mutex m_delay_mutex;

    // 延迟任务队列
    std::vector<DelayOperation> m_delay_tasks;

    // 标识任务线程是否处于活动状态
    volatile bool task_loop_active = true;

    // 用于执行任务的线程
    std::thread m_task_thread;

    // 执行任务的线程函数
    void taskLoop() {
        // 不断执行任务，直到任务线程处于非活动状态
        while (task_loop_active) {
            // 执行所有同步任务
            performSyncTasks();
            {
                // 上锁，保证线程安全
                std::lock_guard<std::mutex> lock(m_async_mutex);

                // 执行所有异步任务
                for (auto &func: m_async_tasks) {
                    func();
                }

                // 清空异步任务队列
                m_async_tasks.clear();
            }

            {
                // 上锁，保证线程安全
                std::lock_guard<std::mutex> delay_lock(m_delay_mutex);

                // 枚举所有延迟任务
                for (auto it = m_delay_tasks.begin(); it != m_delay_tasks.end();) {
                    // 计算从任务创建到现在已经过了多少毫秒
                    auto elapsed_milliseconds =
                            std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::system_clock::now() - it->created_time)
                                    .count();

                    // 如果已经过了延迟时间，则执行任务
                    if (elapsed_milliseconds >= it->milliseconds) {
                        it->func();
                        it = m_delay_tasks.erase(it);
                    } else {
                        ++it;
                    }
                }
            }

            // 线程等待1毫秒
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        printf("threading finished!\n");
    }
};

#endif  //WILIWILI_THREADING_H
