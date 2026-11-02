// Sources/AppDelegate.swift
import UIKit

@UIApplicationMain
final class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        installCrashHandlers()

        // Environment dump on background queue
        DispatchQueue.global(qos: .utility).async {
            dumpEnvironment()
        }

        let fuzzNav = UINavigationController(rootViewController: ViewController())
        fuzzNav.tabBarItem = UITabBarItem(title: "Fuzz", image: UIImage(systemName: "ant"), tag: 0)

        let diagNav = UINavigationController(rootViewController: DiagnosticRunVC())
        diagNav.tabBarItem = UITabBarItem(title: "DiagnosticRun", image: UIImage(systemName: "folder.badge.questionmark"), tag: 1)

        let tabs = UITabBarController()
        tabs.viewControllers = [fuzzNav, diagNav]

        window = UIWindow(frame: UIScreen.main.bounds)
        window?.rootViewController = tabs
        window?.makeKeyAndVisible()
        return true
    }
}
