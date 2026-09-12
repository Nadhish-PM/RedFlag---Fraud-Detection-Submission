-- =====================================================================
-- RedFlag - Fraud Detection Submission
-- Student: Nadhish | Batch: DA-DS-1
-- =====================================================================

USE redflag;

-- =====================================================================
-- PATTERN 1 - VELOCITY FRAUD
-- Looking for users with 30 or more transactions on one calendar date.
-- Expected suspects: about 45-55 user-days.
-- =====================================================================

SELECT user_id,
       DATE(txn_time) AS attack_date,
       COUNT(*) AS daily_txn_count
FROM transactions
GROUP BY user_id, DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY daily_txn_count DESC;

-- Findings: 50 suspect user-days were flagged. Examples include user 14569 with 60 transactions on 2024-04-03 and user 14556 with 60 transactions on 2024-05-28.

-- =====================================================================
-- PATTERN 2 - ROUND-AMOUNT CLUSTERING
-- Looking for users with 15 or more transactions using exact round amounts.
-- Expected suspects: 25.
-- =====================================================================

SELECT user_id,
       COUNT(*) AS round_txn_count
FROM transactions
WHERE amount IN (100, 200, 500, 1000, 2000, 5000, 10000)
GROUP BY user_id
HAVING COUNT(*) >= 15
ORDER BY round_txn_count DESC;

-- Findings: 25 suspect users were flagged. Examples include user 14533, user 14535 and user 14534, each with 30 round-amount transactions.

-- =====================================================================
-- PATTERN 3 - CARD TESTING
-- Looking for users with 30 or more transactions below Rs 10 on one day.
-- Expected suspects: 20.
-- =====================================================================

SELECT user_id,
       DATE(txn_time) AS attack_date,
       COUNT(*) AS small_txn_count
FROM transactions
WHERE amount < 10
GROUP BY user_id, DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY small_txn_count DESC;

-- Findings: 20 suspect user-days were flagged. Examples include user 14556 with 60 small transactions on 2024-05-28 and user 14569 with 60 on 2024-04-03.

-- =====================================================================
-- PATTERN 4 - FAILED-THEN-SUCCEEDED
-- Looking for users with 20 or more failed transactions, which is the simplified signature.
-- Expected suspects: 25.
-- =====================================================================

SELECT user_id,
       COUNT(*) AS failed_txn_count
FROM transactions
WHERE status = 'FAILED'
GROUP BY user_id
HAVING COUNT(*) >= 20
ORDER BY failed_txn_count DESC;

-- Findings: 25 suspect users were flagged. Examples include user 14595 with 35 failed transactions and user 14593 with 34.

-- =====================================================================
-- PATTERN 5 - ODD-HOUR CONCENTRATION
-- Looking for users with at least 30 transactions and at least 80 percent of them between 2 AM and 4 AM.
-- Expected suspects: 20.
-- =====================================================================

SELECT user_id,
       COUNT(*) AS total_txns,
       SUM(CASE WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1 ELSE 0 END) AS odd_hour_txns,
       SUM(CASE WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1 ELSE 0 END) / COUNT(*) AS odd_hour_ratio
FROM transactions
GROUP BY user_id
HAVING COUNT(*) >= 30
   AND SUM(CASE WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1 ELSE 0 END) / COUNT(*) >= 0.80
ORDER BY odd_hour_ratio DESC;

-- Findings: 20 suspect users were flagged. Examples include user 14606 with 49 of 52 transactions in the odd-hour window and user 14609 with 45 of 48.

-- =====================================================================
-- PATTERN 6 - MULE ACCOUNTS
-- Looking for users where 5 or more CREDIT transactions are followed within 30 minutes by a DEBIT of at least 70 percent of the credit amount.
-- Expected suspects: 30.
-- =====================================================================

SELECT c.user_id,
       COUNT(*) AS mule_matches
FROM transactions c
WHERE c.txn_type = 'CREDIT'
  AND EXISTS (
      SELECT 1
      FROM transactions d
      WHERE d.user_id = c.user_id
        AND d.txn_type = 'DEBIT'
        AND d.txn_time > c.txn_time
        AND d.txn_time <= c.txn_time + INTERVAL 30 MINUTE
        AND d.amount >= c.amount * 0.70
  )
GROUP BY c.user_id
HAVING COUNT(*) >= 5
ORDER BY mule_matches DESC;

-- Findings: 30 suspect users were flagged. Examples include user 14630, user 14637 and user 14640, each with 15 matching credit-to-debit instances.

-- =====================================================================
-- PATTERN 7 - REFUND ABUSE
-- Looking for users with 20 or more transactions and a refund ratio above 40 percent.
-- Expected suspects: 24-25.
-- =====================================================================

SELECT user_id,
       COUNT(*) AS total_txns,
       SUM(CASE WHEN txn_type = 'REFUND' THEN 1 ELSE 0 END) AS refund_count,
       SUM(CASE WHEN txn_type = 'REFUND' THEN 1 ELSE 0 END) / COUNT(*) AS refund_ratio
FROM transactions
GROUP BY user_id
HAVING COUNT(*) >= 20
   AND SUM(CASE WHEN txn_type = 'REFUND' THEN 1 ELSE 0 END) / COUNT(*) > 0.40
ORDER BY refund_ratio DESC;

-- Findings: 24 suspect users were flagged. Examples include user 14657 with 36 refunds out of 60 transactions and user 14659 with 34 out of 60.

-- =====================================================================
-- PATTERN 8 - MERCHANT COLLUSION
-- Looking for merchants where the top 5 users by transaction value make up more than 60 percent of the merchant total.
-- Expected suspects: 15 merchants.
-- =====================================================================

WITH user_totals AS (
    SELECT merchant_id,
           user_id,
           SUM(amount) AS user_total
    FROM transactions
    GROUP BY merchant_id, user_id
), ranked_users AS (
    SELECT merchant_id,
           user_id,
           user_total,
           ROW_NUMBER() OVER (PARTITION BY merchant_id ORDER BY user_total DESC) AS user_rank
    FROM user_totals
), merchant_totals AS (
    SELECT merchant_id,
           SUM(amount) AS merchant_total
    FROM transactions
    GROUP BY merchant_id
), top_five AS (
    SELECT merchant_id,
           SUM(user_total) AS top_five_total
    FROM ranked_users
    WHERE user_rank <= 5
    GROUP BY merchant_id
)
SELECT t.merchant_id,
       t.top_five_total,
       m.merchant_total,
       t.top_five_total / m.merchant_total AS top_five_ratio
FROM top_five t
JOIN merchant_totals m ON t.merchant_id = m.merchant_id
WHERE t.top_five_total / m.merchant_total > 0.60
ORDER BY top_five_ratio DESC;

-- Findings: 15 suspect merchants were flagged. Examples include merchant 12 with a top-five share of about 99.91 percent and merchant 8 with about 99.87 percent.

-- =====================================================================
-- PATTERN 9 - JUST-UNDER-THRESHOLD (STRUCTURING)
-- Looking for users with 10 or more transactions at exactly Rs 9,999.
-- Expected suspects: 20.
-- =====================================================================

SELECT user_id,
       COUNT(*) AS threshold_txn_count
FROM transactions
WHERE amount = 9999.00
GROUP BY user_id
HAVING COUNT(*) >= 10
ORDER BY threshold_txn_count DESC;

-- Findings: 20 suspect users were flagged. Examples include user 14690 with 25 transactions and user 14680 with 25 transactions at Rs 9,999.

-- =====================================================================
-- PATTERN 10 - DORMANT-THEN-ACTIVE
-- Looking for a 90+ day gap followed by at least 15 later transactions for the same user.
-- Expected suspects: 25-27.
-- =====================================================================

WITH ordered AS (
    SELECT user_id,
           txn_time,
           LAG(txn_time) OVER (PARTITION BY user_id ORDER BY txn_time) AS previous_time
    FROM transactions
), gaps AS (
    SELECT user_id,
           txn_time AS active_time
    FROM ordered
    WHERE previous_time IS NOT NULL
      AND TIMESTAMPDIFF(DAY, previous_time, txn_time) >= 90
), post_gap AS (
    SELECT g.user_id,
           g.active_time,
           COUNT(t.txn_id) AS transactions_after_gap
    FROM gaps g
    JOIN transactions t
      ON t.user_id = g.user_id
     AND t.txn_time > g.active_time
    GROUP BY g.user_id, g.active_time
)
SELECT user_id,
       MAX(transactions_after_gap) AS transactions_after_gap
FROM post_gap
GROUP BY user_id
HAVING MAX(transactions_after_gap) >= 15
ORDER BY transactions_after_gap DESC;

-- Findings: 26 suspect users were flagged. Examples include user 14526 with a 102.8-day gap followed by 54 transactions and user 14696 with a 109.5-day gap followed by 23.

-- =====================================================================
-- PATTERN 11 - VELOCITY SPIKE
-- Looking for users whose peak monthly transaction count is at least 5 times their six-month average and whose peak is at least 20.
-- Expected suspects: about 35-45.
-- =====================================================================

WITH months AS (
    SELECT 1 AS month_num
    UNION ALL SELECT 2
    UNION ALL SELECT 3
    UNION ALL SELECT 4
    UNION ALL SELECT 5
    UNION ALL SELECT 6
), monthly AS (
    SELECT user_id,
           MONTH(txn_time) AS month_num,
           COUNT(*) AS month_count
    FROM transactions
    GROUP BY user_id, MONTH(txn_time)
), users AS (
    SELECT DISTINCT user_id
    FROM transactions
), monthly_grid AS (
    SELECT u.user_id,
           m.month_num,
           COALESCE(x.month_count, 0) AS month_count
    FROM users u
    CROSS JOIN months m
    LEFT JOIN monthly x
      ON x.user_id = u.user_id
     AND x.month_num = m.month_num
), summary AS (
    SELECT user_id,
           AVG(month_count) AS average_monthly_count,
           MAX(month_count) AS peak_monthly_count,
           SUM(CASE WHEN month_count > 0 THEN 1 ELSE 0 END) AS active_months
    FROM monthly_grid
    GROUP BY user_id
)
SELECT user_id,
       ROUND(average_monthly_count, 2) AS average_monthly_count,
       peak_monthly_count,
       ROUND(peak_monthly_count / average_monthly_count, 2) AS spike_ratio
FROM summary
WHERE peak_monthly_count >= 20
  AND peak_monthly_count / average_monthly_count >= 5
  AND active_months >= 2
ORDER BY spike_ratio DESC;

-- Findings: 45 suspect users were flagged. Examples include user 14733 with a peak of 60 and an average of 12.00, and user 14556 with a peak of 60 and an average of 10.00.

-- =====================================================================
-- PATTERN 12 - GEOGRAPHIC IMPOSSIBILITY
-- Looking for consecutive transactions in different cities within 60 minutes for the same user.
-- Expected suspects: 15.
-- =====================================================================

WITH ordered AS (
    SELECT user_id,
           city,
           txn_time,
           LAG(city) OVER (PARTITION BY user_id ORDER BY txn_time) AS previous_city,
           LAG(txn_time) OVER (PARTITION BY user_id ORDER BY txn_time) AS previous_time
    FROM transactions
)
SELECT DISTINCT user_id
FROM ordered
WHERE previous_city IS NOT NULL
  AND city <> previous_city
  AND TIMESTAMPDIFF(MINUTE, previous_time, txn_time) <= 60
ORDER BY user_id;

-- Findings: 15 suspect users were flagged. Examples include user 14741 moving from Vadodara to Thiruvananthapuram in 30 minutes and from Chandigarh to Pune in 47 minutes.

-- =====================================================================
-- END OF REDFLAG SUBMISSION
-- =====================================================================
