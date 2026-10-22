# Local Foreground Process — 本機候選版

讓 Python 自動化工具啟動一次本機工作、傳入資料、取得輸出，並在逾時或取消時停止相關程序。

這是早期候選工具，採 MIT 授權，詳見 LICENSE。原 HQ 程式及設定不會因本工具而改變。

## 已驗證環境

Windows、Python 3.12。只使用 Python 標準函式庫，不需 API 金鑰或額外套件。其他 Python 版本與 Linux/macOS 尚未在本候選包實機驗證，不列入首版支援承諾。

## 使用

在本目錄執行：

```powershell
python -B examples/demo.py
python -B -m unittest discover -s tests -p test_local_foreground_process.py -q
```

第一個指令示範收取文字及停止逾時工作；第二個執行既有測試。請使用可寫入的系統暫存目錄。

在自己的 Python 程式中，將 scripts 加入模組搜尋路徑後使用 `SupervisedProcessRunner.run`。必要參數為命令陣列 argv、工作目錄 cwd、環境 env（None 表示繼承）、標準輸入 input_bytes。可設定 timeout_seconds、cancel_event 或 authority_ends_at。authority_ends_at 是呼叫端提供的 Unix 時間上限，不是工具授予的權限。

結果包括 returncode、stdout/stderr 原始位元組、timed_out、error_code 與 stop_observation。必須分別檢查錯誤欄位及程序回傳碼；程序本身失敗不一定代表管理工具失敗。取消或逾時可能丟失尚未寫完的資料。

## 界線

- 這不是安全沙箱；傳入的命令具有目前使用者的權限，只執行自己允許的工作。
- 不承諾任意程序都能被停止。遇到 PROCESS_CLEANUP_FAILED，不能認定所有子程序已結束。
- stop_observation 只對同一 Python 程序內的這次執行有意義，不是可傳遞的權限證明。
- stdout/stderr 保留於記憶體，未提供串流或輸出大小限制；不適合大量或無限輸出工作。
- env=None 會繼承環境；輸出不自動去除敏感資料。呼叫端應依實際用途控制環境及顯示內容。
- _exec-wrapper 是內部啟動細節，不是使用者命令列介面。

## 目錄

scripts/ 為工具；tests/ 為對應測試；examples/ 為只執行本機 Python 的示範。沒有私人 HQ Git 歷史、API 憑證、真實工作輸入或執行紀錄。來源與權利的完整發布審查仍記錄在候選包之外。
